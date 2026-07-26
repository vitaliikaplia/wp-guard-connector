<?php
/**
 * Plugin Name:       WP Guard Connector
 * Plugin URI:        https://wpguard.top
 * Description:        Connects this WordPress site to the WP Guard portal — secure registration by API key, an HMAC-signed channel, heartbeat, desired-state sync, one-click SSO and event streaming. Self-updates from GitHub.
 * Version:           1.4.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            WP Guard
 * Author URI:        https://wpguard.top
 * Plugin URI:        https://github.com/vitaliikaplia/wp-guard-connector
 * License:           GPL-2.0-or-later
 *
 * Phase 2.1: registration + signed channel + heartbeat. Phase 2.2/2.3: desired-
 * state PULL (policy enforcement + user/role reconcile). Phase 2.4: one-click
 * wp-admin SSO (redeem a one-time portal ticket, then log the managed user in).
 * Phase 2.5: stream site events (sign-ins, updates) to the portal via signed sync.
 * Phase 2.6: self-update from the public GitHub repo's `master` branch.
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Emergency off-switch. Put  define('WPGUARD_DISABLE', true);  in wp-config.php
 * to fully neutralize the connector — the site owner is NEVER locked out of
 * their own WordPress, whatever the portal has configured. Later phases (which
 * can disable wp-login) honour this same constant to restore standard login.
 */
if (defined('WPGUARD_DISABLE') && WPGUARD_DISABLE) {
    return;
}

/**
 * Channel hardening (mTLS-equivalent): the plugin verifies that the portal SIGNED its
 * responses (per-site HMAC, bound to the request nonce) before trusting security-critical
 * replies — the SSO identity ({uid,email,role} → wp-admin login), the /sync desired-state,
 * and the register secret. This is on by default. As an EMERGENCY valve only (e.g. a portal
 * rollback that ships unsigned replies), you may put  define('WPGUARD_REQUIRE_RESP_SIG', false);
 * in wp-config.php to temporarily accept unsigned responses. Leave it ON in normal operation.
 */

/* Plugin identity + self-update source. Version lives in ONE place (the header is
   parsed by WordPress and by the GitHub updater on the remote side). The branch is
   overridable via wp-config for staging channels; default is the release branch. */
define('WPGUARD_CONNECTOR_VERSION', '1.4.0');
define('WPGUARD_CONNECTOR_FILE', __FILE__);
define('WPGUARD_CONNECTOR_BASENAME', plugin_basename(__FILE__));
define('WPGUARD_CONNECTOR_GITHUB', 'vitaliikaplia/wp-guard-connector');
if (!defined('WPGUARD_CONNECTOR_GITHUB_BRANCH')) {
    define('WPGUARD_CONNECTOR_GITHUB_BRANCH', 'master');
}

require_once __DIR__ . '/includes/class-wpguard-github-updater.php';

final class WP_Guard_Connector {

    const VERSION       = WPGUARD_CONNECTOR_VERSION;
    const OPTION        = 'wpguard_connector';   // array: portal_url, site_id, secret, last_beat, last_status
    const EVENTS_OPTION = 'wpguard_events';      // buffered site events pending upload (autoload=no)
    const EVENTS_MAX    = 500;                    // hard cap on the buffer (drop oldest beyond this)
    const FAILED_MAX_PER_REQUEST = 5;             // cap wp_login_failed events per request (xmlrpc boxcars)
    const CRON_HOOK     = 'wpguard_heartbeat';
    const CRON_SCHEDULE = 'wpguard_10min';

    /** @var WP_Guard_Connector|null */
    private static $instance = null;

    /** Events recorded during THIS request, flushed to the buffer option on shutdown. */
    private $pending = array();

    /** How many failed-login events we've recorded this request (see FAILED_MAX_PER_REQUEST). */
    private $failed_recorded = 0;

    /** True while OUR SSO landing logs a user in, so ev_login doesn't double-record
     *  the wp_login it fires (the portal already logs the jump as sso_jump). */
    private $sso_in_progress = false;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public static function boot() {
        $self = self::instance();
        // Self-update from GitHub (independent of portal connection). Registers the
        // plugin-update-transient + plugins_api filters; the remote check is cached.
        new WP_Guard_Connector_GitHub_Updater();
        add_action('admin_menu', array($self, 'add_settings_page'));
        add_action('admin_post_wpguard_save', array($self, 'handle_save'));
        add_action('admin_post_wpguard_beat', array($self, 'handle_manual_beat'));
        add_action('admin_post_wpguard_disconnect', array($self, 'handle_disconnect'));
        add_filter('cron_schedules', array($self, 'add_cron_schedule'));
        add_action(self::CRON_HOOK, array($self, 'sync'));       // tick pulls desired-state
        add_action('rest_api_init', array($self, 'register_rest')); // inbound poke
        add_action('init', array($self, 'maybe_sso_login'), 1);  // one-click SSO landing
        $self->register_policy_hooks();                          // enforce cached policy
        $self->register_event_hooks();                           // stream site events (2.5)
    }

    /** Register the inbound REST surface: a signature-only poke that triggers an
     *  immediate desired-state pull. Auth IS the HMAC signature (verified in the
     *  handler), so the route is public; the body carries no trusted command. */
    public function register_rest() {
        register_rest_route('wpguard/v1', '/poke', array(
            'methods'             => 'POST',
            'callback'            => array($this, 'rest_poke'),
            'permission_callback' => '__return_true',
        ));
    }

    public function rest_poke($request) {
        if (!$this->is_connected()) {
            return new WP_REST_Response(array('error' => 'not_connected'), 401);
        }
        // Verify against the FIXED poke path the portal signs (independent of the
        // site's permalink structure / how WP routed this request).
        $ok = $this->verify(
            'POST',
            '/wp-json/wpguard/v1/poke',
            $request->get_header('X-WPG-Timestamp'),
            $request->get_header('X-WPG-Nonce'),
            $request->get_header('X-WPG-Signature'),
            $request->get_body()
        );
        if (!$ok) {
            return new WP_REST_Response(array('error' => 'unauthorized'), 401);
        }
        $this->sync(); // pull + reconcile now
        return new WP_REST_Response(array('ok' => true), 200);
    }

    /* ------------------------------------------------------------------ SSO */

    /**
     * One-click SSO landing. The portal opens the user's browser at the site root
     * ('/?wpguard_sso=<jti>'); we redeem that one-time ticket via a SIGNED
     * OUTBOUND callback (the portal burns it and returns who to log in), then set
     * the WP auth cookie and bounce to wp-admin. WordPress needs no inbound port —
     * exactly like the rest of the sync. The site OWNER is never SSO'd (managed
     * users are never the owner); WPGUARD_DISABLE (file top) turns this off.
     */
    public function maybe_sso_login() {
        if (empty($_GET['wpguard_sso'])) {
            return; // cheap early-out on every other request
        }
        if (!$this->is_connected()) {
            return; // no portal secret → can't redeem; leave the request alone
        }
        $jti = sanitize_text_field(wp_unslash($_GET['wpguard_sso']));
        if (!preg_match('/^[0-9a-f]{32}$/', $jti)) {
            $this->sso_fail();
        }

        // Local single-use guard (belt-and-suspenders; the portal burn is the
        // authoritative one). Blocks a double-submit / refresh replaying the jti.
        $tkey = 'wpguard_sso_' . $jti;
        if (get_transient($tkey)) {
            $this->sso_fail();
        }
        set_transient($tkey, 1, 120);

        $r = $this->signed_post('/api/v1/sso/redeem', array('jti' => $jti));
        $res = $r['res']; $nonce = $r['nonce'];
        if (is_wp_error($res) || (int) wp_remote_retrieve_response_code($res) !== 200) {
            $this->sso_fail();
        }
        // Authenticate the identity reply BEFORE trusting {uid,email,role} — a forged reply
        // (fake portal / MITM) could otherwise log an attacker into wp-admin as administrator.
        if (!$this->verify_signed_response($res, $nonce, $this->state()['secret'])) {
            $this->sso_fail();
        }
        $doc = json_decode(wp_remote_retrieve_body($res), true);
        if (!is_array($doc) || empty($doc['uid']) || empty($doc['email'])) {
            $this->sso_fail();
        }

        $uid   = (int) $doc['uid'];
        $email = sanitize_email($doc['email']);
        $name  = isset($doc['name']) ? $doc['name'] : $email;
        $role  = isset($doc['role']) ? $doc['role'] : '';
        if ($email === '') {
            $this->sso_fail();
        }

        // Resolve (or provision) the managed WP user for this portal uid, then make
        // sure it is active with the ticket's role. find_managed_user + provision_user
        // guarantee we never touch the owner or any untagged/hand-made account.
        $wp_user = $this->find_managed_user($uid);
        if (!$wp_user) {
            $wp_user = $this->provision_user($uid, $email, $name);
            if (!$wp_user) {
                $this->sso_fail();
            }
        }
        $this->activate_wp_user($wp_user, $role);

        // Log them in and land on the admin dashboard. Suppress our own event
        // recording for this wp_login — the portal already logged it as sso_jump.
        $this->sso_in_progress = true;
        wp_set_current_user($wp_user->ID);
        wp_set_auth_cookie($wp_user->ID, false, is_ssl());
        do_action('wp_login', $wp_user->user_login, $wp_user);
        nocache_headers();
        wp_safe_redirect(admin_url());
        exit;
    }

    /** SSO failure → a clean, non-leaky dead-end. Never says WHY (no oracle). */
    private function sso_fail() {
        nocache_headers();
        wp_die(
            esc_html__('This WP Guard sign-in link is invalid or has expired. Please start again from the WP Guard portal.', 'wp-guard-connector'),
            esc_html__('Sign-in link expired', 'wp-guard-connector'),
            array('response' => 403, 'back_link' => false)
        );
    }

    /* --------------------------------------------------------------- events */

    /** Register the WordPress-side event hooks we stream to the portal (2.5). Only
     *  a CONNECTED site records; events buffer in memory this request and are
     *  written to the option on shutdown, then uploaded on the next signed sync. */
    public function register_event_hooks() {
        if (!$this->is_connected()) {
            return;
        }
        add_action('wp_login', array($this, 'ev_login'), 10, 2);
        add_action('wp_login_failed', array($this, 'ev_login_failed'), 10, 1);
        add_action('upgrader_process_complete', array($this, 'ev_upgrade'), 10, 2);
        add_action('activated_plugin', array($this, 'ev_plugin_activated'), 10, 2);
        add_action('deactivated_plugin', array($this, 'ev_plugin_deactivated'), 10, 2);
        add_action('shutdown', array($this, 'flush_pending'));
    }

    /** Successful wp-admin sign-in (skipped for our own SSO-driven login). */
    public function ev_login($user_login, $user = null) {
        if ($this->sso_in_progress) {
            return;
        }
        if (!($user instanceof WP_User)) {
            $user = get_user_by('login', $user_login);
        }
        $this->record_event('wp_login', '', $user);
    }

    /** Failed sign-in — no resolved user; the attempted login goes in the label.
     *  Capped per request: one xmlrpc system.multicall can fire wp_login_failed
     *  hundreds of times in a single request, so we record at most a few (enough to
     *  surface the pattern) and drop the rest — no unbounded event/write flood. */
    public function ev_login_failed($username) {
        if ($this->failed_recorded >= self::FAILED_MAX_PER_REQUEST) {
            return;
        }
        $this->failed_recorded++;
        $this->record_event('wp_login_failed', '', null, array('label' => (string) $username));
    }

    /** Core / plugin / theme update or install finished. */
    public function ev_upgrade($upgrader, $hook_extra) {
        if (!is_array($hook_extra) || empty($hook_extra['type'])) {
            return;
        }
        $action = isset($hook_extra['action']) ? $hook_extra['action'] : '';
        if ($action !== 'update' && $action !== 'install') {
            return;
        }
        $type = $hook_extra['type'];
        if ($type === 'core') {
            // No version in the note: get_bloginfo('version') still returns the
            // PRE-update value at this point (the global isn't re-read mid-request),
            // and the new version reaches the portal via the next sync's wp_version.
            $this->record_event('wp_core_updated', '');
        } elseif ($type === 'plugin') {
            $items = !empty($hook_extra['plugins']) ? (array) $hook_extra['plugins']
                : (!empty($hook_extra['plugin']) ? array($hook_extra['plugin']) : array());
            $this->record_event('wp_plugin_updated', $this->slug_list($items));
        } elseif ($type === 'theme') {
            $items = !empty($hook_extra['themes']) ? (array) $hook_extra['themes'] : array();
            $this->record_event('wp_theme_updated', $this->slug_list($items));
        }
    }

    public function ev_plugin_activated($plugin, $network_wide = false) {
        $this->record_event('wp_plugin_activated', $this->slug_list(array($plugin)));
    }

    public function ev_plugin_deactivated($plugin, $network_wide = false) {
        $this->record_event('wp_plugin_deactivated', $this->slug_list(array($plugin)));
    }

    /** Compact a list of plugin/theme paths to a short, comma-joined slug string. */
    private function slug_list($items) {
        $slugs = array();
        foreach ((array) $items as $it) {
            $it = (string) $it;
            $slug = ($it !== '' && strpos($it, '/') !== false) ? dirname($it) : $it;
            $slug = preg_replace('/\.php$/', '', $slug);
            if ($slug !== '') {
                $slugs[] = $slug;
            }
        }
        $slugs = array_slice(array_unique($slugs), 0, 10);
        return implode(', ', $slugs);
    }

    /**
     * Buffer one event. Resolves the actor to a portal uid when the WP user is a
     * WP-Guard-managed account; otherwise keeps a display label. In memory this
     * request; flush_pending() writes the batch to the option on shutdown.
     */
    private function record_event($type, $note = '', $user = null, $extra = array()) {
        $actor_uid = 0;
        $label = isset($extra['label']) ? $extra['label'] : '';
        if ($user instanceof WP_User) {
            $uid = (int) get_user_meta($user->ID, 'wpguard_uid', true);
            if ($uid && get_user_meta($user->ID, 'wpguard_managed', true)) {
                $actor_uid = $uid;
            }
            if ($label === '') {
                $label = $user->display_name !== '' ? $user->display_name : $user->user_login;
            }
        } elseif ($user === null && $label === '') {
            $cur = wp_get_current_user();
            if ($cur && $cur->ID) {
                $uid = (int) get_user_meta($cur->ID, 'wpguard_uid', true);
                if ($uid && get_user_meta($cur->ID, 'wpguard_managed', true)) {
                    $actor_uid = $uid;
                }
                $label = $cur->display_name !== '' ? $cur->display_name : $cur->user_login;
            }
        }

        // No seq here — it is assigned once, in flush_pending, so a request that
        // fires many events (e.g. an xmlrpc boxcar) does a single state write, not one per event.
        $this->pending[] = array(
            'uid'         => bin2hex(random_bytes(16)),
            'type'        => (string) $type,
            'ts'          => time(),
            'actor_uid'   => $actor_uid ? $actor_uid : null,
            'actor_label' => $this->trim_str($label, 80),
            'ip'          => $this->client_ip(),
            'note'        => $this->trim_str($note, 200),
        );
    }

    private function trim_str($s, $max) {
        $s = trim((string) $s);
        return $s === '' ? null : mb_substr($s, 0, $max);
    }

    /** The connecting IP (REMOTE_ADDR only — never a spoofable X-Forwarded-For). */
    private function client_ip() {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null;
    }

    /**
     * Merge this request's events into the buffer option. Assigns monotonic seq
     * numbers here — ONE state write per request regardless of event count. The
     * buffer read-modify-write is serialized by a per-install MySQL named lock so a
     * concurrent request's flush/drop can't clobber it (lost-update → dropped event).
     */
    public function flush_pending() {
        if (empty($this->pending)) {
            return;
        }
        $pending = $this->pending;
        $this->pending = array();

        $this->lock_buffer();
        // One seq write per request (not per event).
        $s = $this->state();
        $seq = isset($s['event_seq']) ? (int) $s['event_seq'] : 0;
        foreach ($pending as &$ev) {
            $ev['seq'] = ++$seq;
        }
        unset($ev);
        $this->save_state(array('event_seq' => $seq));

        $buffer = get_option(self::EVENTS_OPTION, array());
        if (!is_array($buffer)) {
            $buffer = array();
        }
        $buffer = array_merge($buffer, $pending);
        if (count($buffer) > self::EVENTS_MAX) {
            $buffer = array_slice($buffer, count($buffer) - self::EVENTS_MAX);
        }
        update_option(self::EVENTS_OPTION, $buffer, false);
        $this->unlock_buffer();
    }

    /** Up to $limit oldest buffered events, to upload on the next sync. */
    private function peek_events($limit) {
        $buffer = get_option(self::EVENTS_OPTION, array());
        if (!is_array($buffer) || !$buffer) {
            return array();
        }
        return array_slice($buffer, 0, (int) $limit);
    }

    /** Remove delivered events (by uid) from the buffer after the portal acks them.
     *  Serialized by the same buffer lock as flush_pending (see there). */
    private function drop_events($uids) {
        if (empty($uids)) {
            return;
        }
        $drop = array_flip((array) $uids);
        $this->lock_buffer();
        $buffer = get_option(self::EVENTS_OPTION, array());
        if (is_array($buffer)) {
            $kept = array();
            foreach ($buffer as $ev) {
                if (!isset($ev['uid']) || !isset($drop[$ev['uid']])) {
                    $kept[] = $ev;
                }
            }
            update_option(self::EVENTS_OPTION, $kept, false);
        }
        $this->unlock_buffer();
    }

    /** A per-INSTALL MySQL named lock name (hashed from db + prefix) so sites that
     *  share a MySQL server don't serialize against each other. */
    private function buffer_lock_name() {
        global $wpdb;
        return 'wpg_evt_' . substr(md5($wpdb->dbname . '|' . $wpdb->prefix), 0, 24);
    }

    /** Acquire the buffer lock (best-effort: proceed even if it can't be taken, and
     *  it auto-releases when the DB connection ends, so a fatal can't wedge it). */
    private function lock_buffer() {
        global $wpdb;
        $wpdb->query($wpdb->prepare('SELECT GET_LOCK(%s, %d)', $this->buffer_lock_name(), 3));
    }

    private function unlock_buffer() {
        global $wpdb;
        $wpdb->query($wpdb->prepare('SELECT RELEASE_LOCK(%s)', $this->buffer_lock_name()));
    }

    /* ---------------------------------------------------------------- state */

    /** @return array{portal_url:string,site_id:int,secret:string,last_beat:int,last_status:string} */
    public function state() {
        $s = get_option(self::OPTION, array());
        return wp_parse_args(is_array($s) ? $s : array(), array(
            'portal_url'  => 'https://wpguard.top',
            'site_id'     => 0,
            'secret'      => '',
            'last_beat'   => 0,
            'last_status' => '',
        ));
    }

    private function save_state(array $patch) {
        update_option(self::OPTION, array_merge($this->state(), $patch), false);
    }

    public function is_connected() {
        $s = $this->state();
        return $s['site_id'] > 0 && $s['secret'] !== '';
    }

    /** Portal ORIGIN (scheme+host[:port]) — the path is added per request and is
     *  exactly what gets signed, so the portal must be given without a path. */
    private function portal_origin() {
        $url  = $this->state()['portal_url'];
        $p    = wp_parse_url($url);
        if (empty($p['scheme']) || empty($p['host'])) {
            return '';
        }
        $origin = $p['scheme'] . '://' . $p['host'];
        if (!empty($p['port'])) {
            $origin .= ':' . $p['port'];
        }
        return $origin;
    }

    /** Verify TLS except against local dev hosts (.test / localhost), whose certs
     *  the PHP CA bundle doesn't know. Real portal hosts are always verified. */
    private function ssl_verify_for($origin) {
        $host = wp_parse_url($origin, PHP_URL_HOST);
        if (!$host) {
            return true;
        }
        return !(preg_match('/(^|\.)test$/', $host) || $host === 'localhost' || $host === '127.0.0.1');
    }

    /* ------------------------------------------------------------- crypto */

    /** Canonical string mirroring lib/connector.js — order and separators must
     *  match the portal byte-for-byte. `$body` is the exact request-body string. */
    private function canonical($method, $path, $ts, $nonce, $body) {
        return strtoupper($method) . "\n" . $path . "\n" . $ts . "\n" . $nonce . "\n" . hash('sha256', $body);
    }

    private function sign($secret, $method, $path, $ts, $nonce, $body) {
        return hash_hmac('sha256', $this->canonical($method, $path, $ts, $nonce, $body), $secret);
    }

    /* --------------------------------------------------------------- HTTP */

    /**
     * POST a signed JSON request to a portal endpoint path. Returns
     * array('res' => <wp_remote_post result | WP_Error>, 'nonce' => <request nonce>) so the
     * caller can bind the portal's RESPONSE signature to the exact request it made.
     */
    private function signed_post($path, array $payload) {
        $origin = $this->portal_origin();
        $state  = $this->state();
        if ($origin === '' || !$this->is_connected()) {
            return array('res' => new WP_Error('not_connected', 'Not connected to a portal.'), 'nonce' => '');
        }
        $body  = wp_json_encode($payload);
        $ts    = (string) time();
        $nonce = bin2hex(random_bytes(16));
        $sig   = $this->sign($state['secret'], 'POST', $path, $ts, $nonce, $body);

        $res = wp_remote_post($origin . $path, array(
            'timeout'   => 15,
            'sslverify' => $this->ssl_verify_for($origin),
            'headers'   => array(
                'Content-Type'     => 'application/json',
                'X-WPG-Site'       => (string) $state['site_id'],
                'X-WPG-Timestamp'  => $ts,
                'X-WPG-Nonce'      => $nonce,
                'X-WPG-Signature'  => $sig,
            ),
            'body'      => $body,
        ));
        return array('res' => $res, 'nonce' => $nonce);
    }

    /** Whether to REQUIRE a valid portal response signature (mTLS-equivalent). Default: yes.
     *  Emergency valve: define('WPGUARD_REQUIRE_RESP_SIG', false) in wp-config.php if a
     *  portal-side rollback ever ships unsigned replies (see the file-top note). */
    private function require_resp_sig() {
        if (defined('WPGUARD_REQUIRE_RESP_SIG')) {
            return (bool) WPGUARD_REQUIRE_RESP_SIG;
        }
        return true;
    }

    /** Verify a portal RESPONSE signature. Mirrors the portal's connector.signResponse:
     *  canonical = "RESP\n<request-nonce>\n<resp-ts>\nsha256(body)", HMAC-SHA256 with $key
     *  (the per-site secret for signed endpoints; sha256(api_key) for register). Constant-
     *  time compare + a ±300s freshness window on the response timestamp. */
    private function verify_response($body, $nonce, $resp_ts, $sig_header, $key) {
        if ($key === '' || $sig_header === '' || $resp_ts === '') {
            return false;
        }
        if (abs(time() - (int) $resp_ts) > 300) {
            return false;
        }
        $sig       = (strpos($sig_header, 'sha256=') === 0) ? substr($sig_header, 7) : $sig_header;
        $canonical = "RESP\n" . $nonce . "\n" . $resp_ts . "\n" . hash('sha256', (string) $body);
        $expected  = hash_hmac('sha256', $canonical, (string) $key);
        return hash_equals($expected, (string) $sig);
    }

    /** Verify a wp_remote_post RESPONSE (headers + body) bound to the request $nonce, using
     *  $key. Returns true when enforcement is disabled; otherwise false on a missing/invalid
     *  signature — the caller then rejects the reply (keeps prior policy / refuses SSO). */
    private function verify_signed_response($res, $nonce, $key) {
        if (!$this->require_resp_sig()) {
            return true;
        }
        return $this->verify_response(
            (string) wp_remote_retrieve_body($res),
            (string) $nonce,
            (string) wp_remote_retrieve_header($res, 'x-wpg-resp-timestamp'),
            (string) wp_remote_retrieve_header($res, 'x-wpg-resp-signature'),
            (string) $key
        );
    }

    /* ------------------------------------------------------- register / beat */

    /**
     * Register (or re-register) with the portal using the one-time API key.
     * On success stores the returned site_id + per-site HMAC secret.
     * @return array{ok:bool,error?:string}
     */
    public function register($api_key) {
        $origin = $this->portal_origin();
        if ($origin === '') {
            return array('ok' => false, 'error' => 'Set a valid portal URL first.');
        }
        $api_key = trim((string) $api_key);
        if ($api_key === '') {
            return array('ok' => false, 'error' => 'Enter the site API key from the portal.');
        }

        $res = wp_remote_post($origin . '/api/v1/register', array(
            'timeout'   => 15,
            'sslverify' => $this->ssl_verify_for($origin),
            'headers'   => array('Content-Type' => 'application/json'),
            'body'      => wp_json_encode(array(
                'api_key'        => $api_key,
                'site_url'       => home_url(),
                'wp_version'     => get_bloginfo('version'),
                'plugin_version' => self::VERSION,
            )),
        ));

        if (is_wp_error($res)) {
            return array('ok' => false, 'error' => $res->get_error_message());
        }
        $code = wp_remote_retrieve_response_code($res);
        // Authenticate the register reply with a key DERIVED from the API key we presented
        // (the per-site secret it delivers can't sign itself). Register has no request nonce.
        if ($code === 200 && !$this->verify_signed_response($res, '', hash('sha256', $api_key))) {
            return array('ok' => false, 'error' => 'Registration response failed verification.');
        }
        $json = json_decode(wp_remote_retrieve_body($res), true);
        if ($code !== 200 || empty($json['site_id']) || empty($json['secret'])) {
            $err = is_array($json) && !empty($json['error']) ? $json['error'] : ('HTTP ' . $code);
            return array('ok' => false, 'error' => 'Registration rejected: ' . $err);
        }

        $this->save_state(array(
            'site_id'        => (int) $json['site_id'],
            'secret'         => (string) $json['secret'],
            // Reset the applied baseline so the very next sync re-applies the
            // portal's desired-state — a re-added site starts at config_version=1
            // and must not be rejected by the monotonic gate against a stale value.
            'config_version' => 0,
            'policy'         => array(),
            'last_beat'      => time(),
            'last_status'    => 'registered',
        ));
        $this->ensure_cron();
        $this->sync(); // pull + apply desired-state (policy) right away
        return array('ok' => true);
    }

    /* ------------------------------------------------------- sync / policy */

    /** Config version this site has already applied. */
    private function applied_config_version() {
        $s = $this->state();
        return isset($s['config_version']) ? (int) $s['config_version'] : 0;
    }

    /** Cached desired policy (applied on the last sync). */
    private function policy() {
        $s = $this->state();
        return (isset($s['policy']) && is_array($s['policy'])) ? $s['policy'] : array();
    }

    /**
     * Signed sync tick: report liveness + our applied config_version, pull the
     * portal's desired-state, reconcile. Replaces the plain heartbeat.
     * @return array{ok:bool,error?:string}
     */
    public function sync() {
        // Piggyback any buffered site events (2.5) onto this signed pull.
        $events = $this->peek_events(100);
        $r = $this->signed_post('/api/v1/sync', array(
            'wp_version'     => get_bloginfo('version'),
            'latest_core'    => $this->latest_core_version(),
            'plugin_version' => self::VERSION,
            'config_version' => $this->applied_config_version(),
            'events'         => $events,
        ));
        $res = $r['res']; $nonce = $r['nonce'];
        if (is_wp_error($res)) {
            $this->save_state(array('last_status' => 'error: ' . $res->get_error_message()));
            return array('ok' => false, 'error' => $res->get_error_message());
        }
        $code = wp_remote_retrieve_response_code($res);
        if ($code !== 200) {
            $patch = array('last_beat' => time(), 'last_status' => 'rejected: HTTP ' . $code);
            if ($code === 401 || $code === 404) {
                // The portal no longer accepts us (key rotated / site removed) →
                // stop enforcing a policy we can no longer refresh, so the owner is
                // never trapped by a site the portal has cut loose.
                $patch['policy'] = array();
                $patch['config_version'] = 0;
            }
            $this->save_state($patch);
            return array('ok' => false, 'error' => 'HTTP ' . $code);
        }
        // Authenticate the RESPONSE before trusting the desired-state it carries. A forged
        // /sync reply could push a hostile policy/roster; reject it and keep the current cache.
        if (!$this->verify_signed_response($res, $nonce, $this->state()['secret'])) {
            $this->save_state(array('last_beat' => time(), 'last_status' => 'error: bad response signature'));
            return array('ok' => false, 'error' => 'bad_response_signature');
        }
        $doc = json_decode(wp_remote_retrieve_body($res), true);
        $this->apply_desired_state(is_array($doc) ? $doc : array());
        // Drop only events the portal acknowledged ingesting; a failed ingest is
        // retried next tick (INSERT IGNORE on the portal makes a resend harmless).
        if ($events && is_array($doc) && !empty($doc['events_ack'])) {
            $this->drop_events(wp_list_pluck($events, 'uid'));
        }
        $this->save_state(array('last_beat' => time(), 'last_status' => 'ok'));
        return array('ok' => true);
    }

    /**
     * Reconcile to the portal's desired-state. Idempotent: only applies a strictly
     * newer config_version, so replays and stale docs are no-ops. (User-roster
     * reconcile lands in Step 2.3; for now we cache policy for the login hooks.)
     */
    public function apply_desired_state($doc) {
        if (empty($doc['config_version'])) {
            return;
        }
        $incoming = (int) $doc['config_version'];
        if ($incoming <= $this->applied_config_version()) {
            return;
        }
        $policy = (isset($doc['policy']) && is_array($doc['policy'])) ? array(
            'wp_login_disabled' => !empty($doc['policy']['wp_login_disabled']),
            'twofa_enforced'    => !empty($doc['policy']['twofa_enforced']),
        ) : array();
        if (isset($doc['users']) && is_array($doc['users'])) {
            $this->reconcile_users($doc['users']);
        }
        $this->save_state(array('config_version' => $incoming, 'policy' => $policy));
    }

    /* ---------------------------------------------------- user reconcile */

    /**
     * Converge WP users to the portal roster. Only ever touches accounts WE
     * provisioned (tagged wpguard_managed) — the owner and any hand-made WP
     * accounts are never mutated. Mapping is by a stable portal uid, never by
     * email adoption: an email collision with an untagged account is refused.
     */
    private function reconcile_users($roster) {
        $seen = array();
        foreach ($roster as $u) {
            if (empty($u['uid'])) {
                continue;
            }
            $uid = (int) $u['uid'];
            // Mark present BEFORE the email check — a roster entry with an unusable
            // email must skip only its own provision/update, never fall through to
            // deprovision-by-absence and block a still-authorized user.
            $seen[$uid] = true;
            $email = isset($u['email']) ? sanitize_email($u['email']) : '';
            if ($email === '') {
                continue;
            }

            $wp_user = $this->find_managed_user($uid);
            if (!$wp_user) {
                $existing = get_user_by('email', $email);
                if ($existing) {
                    if (!get_user_meta($existing->ID, 'wpguard_managed', true)) {
                        continue; // untagged account with this email → refuse, fail closed
                    }
                    // A managed account with this email but no/other uid tag → adopt it.
                    $wp_user = $existing;
                    update_user_meta($wp_user->ID, 'wpguard_uid', $uid);
                    update_user_meta($wp_user->ID, 'wpguard_managed', '1');
                } else {
                    $wp_user = $this->provision_user($uid, $email, isset($u['name']) ? $u['name'] : $email);
                    if (!$wp_user) {
                        continue;
                    }
                }
            }

            $state = isset($u['state']) ? $u['state'] : 'active';
            if ($state === 'blocked') {
                $this->block_wp_user($wp_user);
            } else {
                $this->activate_wp_user($wp_user, isset($u['role']) ? $u['role'] : '');
            }
        }

        // Deprovision-by-absence: a managed user no longer in the roster (their
        // portal access was revoked) is blocked — the owner is never touched.
        $managed = get_users(array(
            'meta_key' => 'wpguard_managed', 'meta_value' => '1', 'fields' => array('ID'),
        ));
        foreach ($managed as $m) {
            $muid = (int) get_user_meta($m->ID, 'wpguard_uid', true);
            if (isset($seen[$muid])) {
                continue;
            }
            $wp_user = get_user_by('id', $m->ID);
            if ($wp_user && !$this->is_owner($wp_user)) {
                $this->block_wp_user($wp_user);
            }
        }
    }

    /** Find the WP user we provisioned for a given portal uid, or null. */
    private function find_managed_user($uid) {
        $users = get_users(array(
            'meta_query' => array(
                'relation' => 'AND',
                array('key' => 'wpguard_managed', 'value' => '1'),
                array('key' => 'wpguard_uid', 'value' => (string) $uid),
            ),
            'number' => 1,
        ));
        return $users ? $users[0] : null;
    }

    /** Create a fresh WP user tagged as WP-Guard-managed. */
    private function provision_user($uid, $email, $name) {
        // Never shadow the owner's recovery address, even if it has no WP account yet.
        if (strtolower($email) === strtolower((string) get_option('admin_email'))) {
            return null;
        }
        $user_id = wp_insert_user(array(
            'user_login'   => $this->unique_login($email),
            'user_email'   => $email,
            'user_pass'    => wp_generate_password(24, true, true),
            'display_name' => $name !== '' ? $name : $email,
            'role'         => '', // set by activate/block right after
        ));
        if (is_wp_error($user_id)) {
            return null;
        }
        update_user_meta($user_id, 'wpguard_uid', (int) $uid);
        update_user_meta($user_id, 'wpguard_managed', '1');
        return get_user_by('id', $user_id);
    }

    /** A unique, WP-Guard-prefixed login derived from the email local-part. */
    private function unique_login($email) {
        $base = sanitize_user(current(explode('@', $email)), true);
        if ($base === '') {
            $base = 'user';
        }
        $login = 'wpg_' . $base;
        $i = 1;
        while (username_exists($login)) {
            $login = 'wpg_' . $base . '_' . (++$i);
        }
        return $login;
    }

    /** Map a portal role slug to a role that exists on THIS site; unknown slugs
     *  (e.g. shop_manager / seo_manager on a vanilla site) fall back to the safe
     *  minimal 'subscriber' rather than silently granting nothing or too much. */
    private function map_role($slug) {
        $slug = is_string($slug) ? $slug : '';
        if ($slug !== '' && get_role($slug)) {
            return $slug;
        }
        return 'subscriber';
    }

    /** Bring a managed user to active with exactly the desired role. */
    private function activate_wp_user($user, $role) {
        delete_user_meta($user->ID, 'wpguard_blocked');
        $user->set_role($this->map_role($role)); // replaces any prior managed role
    }

    /** Block a managed user: strip all caps, tag as blocked, kill sessions. The
     *  owner is never blocked (defence-in-depth against a bad roster). */
    private function block_wp_user($user) {
        if ($this->is_owner($user)) {
            return;
        }
        update_user_meta($user->ID, 'wpguard_blocked', '1');
        $user->set_role('');
        $sessions = WP_Session_Tokens::get_instance($user->ID);
        if ($sessions) {
            $sessions->destroy_all();
        }
    }

    /**
     * Refuse authentication for a blocked MANAGED account — across wp-login,
     * xmlrpc.php and REST Application Passwords. Keyed on the RESOLVED account's
     * own wpguard_blocked usermeta (never a portal-supplied email string), and
     * the owner is always exempt — so a hostile/buggy roster can never deny the
     * site owner (or any untagged account) their own login.
     */
    public function enforce_blocked($user, $username = '', $password = '') {
        if (!($user instanceof WP_User)) {
            return $user; // bad creds / unresolved → leave WP's flow untouched
        }
        if ($this->is_owner($user)) {
            return $user;
        }
        if (get_user_meta($user->ID, 'wpguard_blocked', true)) {
            return new WP_Error('wpguard_blocked', __('This account is blocked in WP Guard.', 'wp-guard-connector'));
        }
        return $user;
    }

    /** Register the login hooks that enforce the currently-cached policy. Only a
     *  CONNECTED site enforces — a disconnected one always restores standard login,
     *  so an owner who disconnects (or whose key was rotated) is never trapped by a
     *  stale cache. */
    public function register_policy_hooks() {
        if (!$this->is_connected()) {
            return;
        }
        // Blocked managed users can never sign in (belt-and-suspenders alongside
        // the role-strip + session-destroy done at reconcile time). Always on when
        // connected, independent of policy toggles.
        add_filter('authenticate', array($this, 'enforce_blocked'), 40, 3);
        $policy = $this->policy();
        if (!empty($policy['wp_login_disabled'])) {
            // Redirect the browser login page (UX) AND block password auth at the
            // authenticate layer — the latter also covers xmlrpc.php and REST
            // Application Passwords, which login_init never sees.
            add_action('login_init', array($this, 'enforce_login_redirect'), 0);
            add_filter('authenticate', array($this, 'enforce_login_disabled'), 30, 1);
        }
        if (!empty($policy['twofa_enforced'])) {
            add_filter('authenticate', array($this, 'enforce_managed_2fa'), 30, 1);
        }
    }

    /**
     * Block direct PASSWORD authentication for everyone but the owner while
     * wp_login_disabled is on — across wp-login.php, xmlrpc.php and REST
     * Application Passwords (all route through the `authenticate` filter). Bad
     * credentials still surface WP's own error; the owner keeps a password valve
     * and WPGUARD_DISABLE is the full escape.
     */
    public function enforce_login_disabled($user) {
        if (!($user instanceof WP_User)) {
            return $user; // WP_Error (bad creds) / null → leave WP's flow untouched
        }
        if ($this->is_owner($user)) {
            return $user;
        }
        return new WP_Error('wpguard_login_disabled', __('Direct login is disabled — sign in through WP Guard.', 'wp-guard-connector'));
    }

    /**
     * "All logins go through WP Guard": send direct wp-login visitors to the
     * portal. The site OWNER is never locked out — `define('WPGUARD_DISABLE',true)`
     * in wp-config.php disables the whole connector (checked at file top) and
     * restores standard login. Logout is never trapped.
     */
    public function enforce_login_redirect() {
        if (!$this->is_connected()) {
            return; // disconnected → never enforce (standard login restored)
        }
        if (is_user_logged_in()) {
            return; // already signed in — don't loop them out
        }
        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
        if (in_array($action, array('logout', 'postpass'), true)) {
            return;
        }
        $portal = $this->portal_origin();
        if ($portal === '') {
            return; // misconfigured portal → fail open rather than lock the site
        }
        // wp_safe_redirect() only allows same-host targets by default; whitelist
        // the (admin-configured, trusted) portal host so the cross-host redirect
        // isn't silently downgraded to wp-admin/.
        $portal_host = wp_parse_url($portal, PHP_URL_HOST);
        add_filter('allowed_redirect_hosts', function ($hosts) use ($portal_host) {
            if ($portal_host) {
                $hosts[] = $portal_host;
            }
            return $hosts;
        });
        nocache_headers();
        wp_safe_redirect($portal . '/login/', 302);
        exit;
    }

    /**
     * When 2FA is enforced, funnel OUR managed users through the portal (block
     * their direct password login). The owner and any non-managed WordPress
     * accounts keep normal login. Inert until Step 2.3 provisions managed users.
     */
    public function enforce_managed_2fa($user) {
        if (!($user instanceof WP_User)) {
            return $user;
        }
        if (!get_user_meta($user->ID, 'wpguard_managed', true)) {
            return $user; // not ours → untouched
        }
        if ($this->is_owner($user)) {
            return $user;
        }
        return new WP_Error('wpguard_sso_required', __('Please sign in through WP Guard.', 'wp-guard-connector'));
    }

    /** Owner check (any match): WP user ID 1, the admin_email account, or a
     *  WPGUARD_OWNER_LOGIN constant. Used to keep the owner out of enforcement.
     *  A WP-Guard-managed account can NEVER be the owner — otherwise a provisioned
     *  account whose email happens to equal admin_email would become immune to
     *  block/deprovision (spoofing the owner exemption). ID 1 is inherently safe
     *  (it is never provisioned), so it stays an unconditional match. */
    private function is_owner($user) {
        if (!($user instanceof WP_User)) {
            return false;
        }
        if ((int) $user->ID === 1) {
            return true;
        }
        if (get_user_meta($user->ID, 'wpguard_managed', true)) {
            return false; // our own provisioned account → never treated as owner
        }
        if (strtolower($user->user_email) === strtolower((string) get_option('admin_email'))) {
            return true;
        }
        if (defined('WPGUARD_OWNER_LOGIN') && $user->user_login === WPGUARD_OWNER_LOGIN) {
            return true;
        }
        return false;
    }

    /**
     * Verify an INBOUND signed request (portal→plugin: poke, later). Mirrors
     * lib/connector.verify — timestamp window, constant-time signature, one-time
     * nonce (WP transient). Used from Step 2.3 onward.
     */
    public function verify($method, $path, $ts, $nonce, $signature, $body) {
        $secret = $this->state()['secret'];
        if (!$secret || !$signature || !$nonce || $ts === '') {
            return false;
        }
        if (abs(time() - (int) $ts) > 300) {
            return false;
        }
        $expected = $this->sign($secret, $method, $path, $ts, $nonce, $body);
        if (!hash_equals($expected, (string) $signature)) {
            return false;
        }
        $key = 'wpguard_nonce_' . preg_replace('/[^a-f0-9]/', '', (string) $nonce);
        if (get_transient($key)) {
            return false; // replay
        }
        set_transient($key, 1, 600);
        return true;
    }

    /**
     * The newest WordPress core version available to THIS site, read from WordPress's
     * OWN local update cache (the update_core transient) — no network call here; WP
     * refreshes that cache on its twice-daily wp_version_check cron. Returns the running
     * version when up to date, or when the update API isn't loadable in this context,
     * and NEVER a version below the running one — so the portal's `wp_version <> latest_wp`
     * "behind" test stays exact.
     */
    private function latest_core_version() {
        $current = (string) get_bloginfo('version');
        if (!function_exists('get_preferred_from_update_core')) {
            $inc = ABSPATH . 'wp-admin/includes/update.php';
            if (is_readable($inc)) {
                require_once $inc;
            }
        }
        if (!function_exists('get_preferred_from_update_core')) {
            return $current; // update API unavailable here → safe no-op (portal keeps prior value)
        }
        $u = get_preferred_from_update_core();
        if (is_object($u) && !empty($u->current) && isset($u->response)
            && $u->response === 'upgrade'
            && version_compare((string) $u->current, $current, '>')) {
            return (string) $u->current;
        }
        return $current;
    }

    /**
     * Send a signed heartbeat. Refreshes portal-side liveness + reported versions.
     * @return array{ok:bool,error?:string}
     */
    public function heartbeat() {
        $r = $this->signed_post('/api/v1/heartbeat', array(
            'wp_version'     => get_bloginfo('version'),
            'latest_core'    => $this->latest_core_version(),
            'plugin_version' => self::VERSION,
        ));
        $res = $r['res']; // heartbeat body carries no trusted data → no response-sig gate
        if (is_wp_error($res)) {
            $this->save_state(array('last_status' => 'error: ' . $res->get_error_message()));
            return array('ok' => false, 'error' => $res->get_error_message());
        }
        $code = wp_remote_retrieve_response_code($res);
        $ok   = ($code === 200);
        $this->save_state(array(
            'last_beat'   => time(),
            'last_status' => $ok ? 'ok' : ('rejected: HTTP ' . $code),
        ));
        return array('ok' => $ok, 'error' => $ok ? '' : ('HTTP ' . $code));
    }

    /* ---------------------------------------------------------------- cron */

    public function add_cron_schedule($schedules) {
        $schedules[self::CRON_SCHEDULE] = array('interval' => 600, 'display' => 'Every 10 minutes (WP Guard)');
        return $schedules;
    }

    private function ensure_cron() {
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 600, self::CRON_SCHEDULE, self::CRON_HOOK);
        }
    }

    public static function activate() {
        // Cron is (re)ensured on registration; nothing required at activation.
    }

    public static function deactivate() {
        $ts = wp_next_scheduled(self::CRON_HOOK);
        if ($ts) {
            wp_unschedule_event($ts, self::CRON_HOOK);
        }
    }

    /* ------------------------------------------------------------ admin UI */

    public function add_settings_page() {
        add_options_page('WP Guard', 'WP Guard', 'manage_options', 'wp-guard-connector', array($this, 'render_settings_page'));
    }

    public function handle_save() {
        if (!current_user_can('manage_options')) {
            wp_die('Forbidden');
        }
        check_admin_referer('wpguard_save');
        $portal = isset($_POST['portal_url']) ? esc_url_raw(wp_unslash($_POST['portal_url'])) : '';
        $this->save_state(array('portal_url' => $portal));

        $notice = 'saved';
        $api_key = isset($_POST['api_key']) ? sanitize_text_field(wp_unslash($_POST['api_key'])) : '';
        if ($api_key !== '') {
            $r = $this->register($api_key);
            $notice = $r['ok'] ? 'connected' : ('err:' . $r['error']);
        }
        $this->redirect_back($notice);
    }

    public function handle_manual_beat() {
        if (!current_user_can('manage_options')) {
            wp_die('Forbidden');
        }
        check_admin_referer('wpguard_beat');
        $r = $this->sync();
        $this->redirect_back($r['ok'] ? 'beat' : ('err:' . $r['error']));
    }

    public function handle_disconnect() {
        if (!current_user_can('manage_options')) {
            wp_die('Forbidden');
        }
        check_admin_referer('wpguard_disconnect');
        self::deactivate();
        // Drop any buffered events — a disconnected site has no portal to ship them to.
        delete_option(self::EVENTS_OPTION);
        // Clear the enforcement cache too — a disconnected site must restore
        // standard login, not keep redirecting to a portal it no longer talks to.
        $this->save_state(array(
            'site_id' => 0, 'secret' => '', 'policy' => array(), 'config_version' => 0,
            'event_seq' => 0, 'last_status' => 'disconnected',
        ));
        $this->redirect_back('disconnected');
    }

    private function redirect_back($notice) {
        wp_safe_redirect(add_query_arg('wpg', rawurlencode($notice), admin_url('options-general.php?page=wp-guard-connector')));
        exit;
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $s      = $this->state();
        $notice = isset($_GET['wpg']) ? sanitize_text_field(wp_unslash($_GET['wpg'])) : '';
        $post   = admin_url('admin-post.php');
        ?>
        <div class="wrap">
            <h1>WP Guard Connector</h1>
            <?php $this->render_notice($notice); ?>

            <h2>Connection</h2>
            <table class="form-table" role="presentation">
                <tr>
                    <th>Status</th>
                    <td>
                        <?php if ($this->is_connected()) : ?>
                            <strong style="color:#15803d">Connected</strong> — site #<?php echo (int) $s['site_id']; ?>
                        <?php else : ?>
                            <strong style="color:#b45309">Not connected</strong>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php if ($s['last_beat']) : ?>
                <tr>
                    <th>Last heartbeat</th>
                    <td><?php echo esc_html(human_time_diff($s['last_beat']) . ' ago'); ?> — <?php echo esc_html($s['last_status']); ?></td>
                </tr>
                <?php endif; ?>
            </table>

            <form method="post" action="<?php echo esc_url($post); ?>">
                <input type="hidden" name="action" value="wpguard_save">
                <?php wp_nonce_field('wpguard_save'); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th><label for="wpg_portal">Portal URL</label></th>
                        <td>
                            <input name="portal_url" id="wpg_portal" type="url" class="regular-text"
                                   value="<?php echo esc_attr($s['portal_url']); ?>" placeholder="https://wpguard.top">
                            <p class="description">Origin of your WP Guard portal (no path). Local dev: <code>http://localhost:3000</code>.</p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="wpg_key">Site API key</label></th>
                        <td>
                            <input name="api_key" id="wpg_key" type="text" class="regular-text" autocomplete="off"
                                   placeholder="wpg_live_… (shown once when you add the site in the portal)">
                            <p class="description">Paste to connect (or reconnect). It is used once to register and is not stored.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button($this->is_connected() ? 'Save / Reconnect' : 'Connect'); ?>
            </form>

            <?php if ($this->is_connected()) : ?>
                <div style="display:flex;gap:10px">
                    <form method="post" action="<?php echo esc_url($post); ?>">
                        <input type="hidden" name="action" value="wpguard_beat">
                        <?php wp_nonce_field('wpguard_beat'); ?>
                        <?php submit_button('Sync now', 'secondary', 'submit', false); ?>
                    </form>
                    <form method="post" action="<?php echo esc_url($post); ?>" onsubmit="return confirm('Disconnect this site from the portal?');">
                        <input type="hidden" name="action" value="wpguard_disconnect">
                        <?php wp_nonce_field('wpguard_disconnect'); ?>
                        <?php submit_button('Disconnect', 'delete', 'submit', false); ?>
                    </form>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }

    private function render_notice($notice) {
        if ($notice === '') {
            return;
        }
        if (strpos($notice, 'err:') === 0) {
            printf('<div class="notice notice-error"><p>%s</p></div>', esc_html(substr($notice, 4)));
            return;
        }
        $map = array(
            'connected'    => 'Connected to the portal.',
            'saved'        => 'Settings saved.',
            'beat'         => 'Heartbeat sent.',
            'disconnected' => 'Disconnected locally.',
        );
        if (isset($map[$notice])) {
            printf('<div class="notice notice-success"><p>%s</p></div>', esc_html($map[$notice]));
        }
    }
}

register_activation_hook(__FILE__, array('WP_Guard_Connector', 'activate'));
register_deactivation_hook(__FILE__, array('WP_Guard_Connector', 'deactivate'));
WP_Guard_Connector::boot();

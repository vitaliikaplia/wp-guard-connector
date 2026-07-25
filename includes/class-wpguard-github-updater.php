<?php
/**
 * GitHub self-updater for WP Guard Connector.
 *
 * Serves plugin updates from the public repository's release branch (default
 * `master`): WordPress asks "is there an update?" and we answer by comparing the
 * installed version to the `Version:` header of the plugin's main file on GitHub
 * (raw), handing WordPress the branch archive as the package. No portal
 * involvement, no third-party library. The remote check is cached (12h; a manual
 * "Check again" with ?force-check=1 bypasses it).
 */

if (!defined('ABSPATH')) {
    exit;
}

final class WP_Guard_Connector_GitHub_Updater {

    const CACHE_KEY = 'wpguard_connector_update_data';
    const CACHE_TTL = 43200; // 12 hours

    public function __construct() {
        add_filter('pre_set_site_transient_update_plugins', array($this, 'filter_update_plugins_transient'));
        add_filter('site_transient_update_plugins', array($this, 'filter_update_plugins_transient'));
        add_filter('plugins_api', array($this, 'filter_plugins_api'), 10, 3);
        add_filter('upgrader_source_selection', array($this, 'normalize_github_source_directory'), 11, 4);
        add_action('delete_site_transient_update_plugins', array($this, 'clear_cached_update_data'));
        add_action('upgrader_process_complete', array($this, 'clear_cache_after_update'), 10, 2);
    }

    /** Inject our update into WP's plugin-update transient (or record "no update"). */
    public function filter_update_plugins_transient($transient) {
        if (!is_object($transient)) {
            $transient = new stdClass();
        }
        if (empty($transient->checked) || !is_array($transient->checked)) {
            return $transient;
        }

        $basename = WPGUARD_CONNECTOR_BASENAME;
        $local_version = isset($transient->checked[$basename]) ? $transient->checked[$basename] : WPGUARD_CONNECTOR_VERSION;
        $remote_data = $this->get_remote_update_data($this->should_force_check());
        if (!$remote_data || empty($remote_data['version'])) {
            return $transient;
        }

        if (empty($transient->response) || !is_array($transient->response)) {
            $transient->response = array();
        }
        if (empty($transient->no_update) || !is_array($transient->no_update)) {
            $transient->no_update = array();
        }

        $update = $this->build_update_response($remote_data);
        if (version_compare($remote_data['version'], $local_version, '>')) {
            $transient->response[$basename] = $update;
            unset($transient->no_update[$basename]);
        } else {
            $transient->no_update[$basename] = $update;
            unset($transient->response[$basename]);
        }

        return $transient;
    }

    /** Provide the "View details" modal data for our slug. */
    public function filter_plugins_api($result, $action, $args) {
        if ($action !== 'plugin_information' || empty($args->slug) || $args->slug !== $this->get_slug()) {
            return $result;
        }
        $remote_data = $this->get_remote_update_data($this->should_force_check());
        $version = isset($remote_data['version']) ? $remote_data['version'] : WPGUARD_CONNECTOR_VERSION;

        return (object) array(
            'name'         => 'WP Guard Connector',
            'slug'         => $this->get_slug(),
            'version'      => $version,
            'author'       => '<a href="https://wpguard.top/">WP Guard</a>',
            'homepage'     => $this->get_repository_url(),
            'requires'     => '6.0',
            'requires_php' => '7.4',
            'tested'       => get_bloginfo('version'),
            'download_link' => isset($remote_data['package']) ? $remote_data['package'] : $this->get_package_url(),
            'sections'     => array(
                'description' => '<p>Connects this WordPress site to the WP Guard portal: secure HMAC channel, desired-state sync, one-click SSO and event streaming.</p>',
                'changelog'   => '<p>Updates load from the <code>' . esc_html($this->get_branch()) . '</code> branch of the public GitHub repository when its plugin header version is newer than the installed version.</p>',
            ),
        );
    }

    /**
     * A GitHub archive extracts as "<repo>-<branch>/"; WordPress expects the folder
     * to be the plugin slug. Rename the unpacked source so the update lands in the
     * right place (only for our own plugin).
     */
    public function normalize_github_source_directory($source, $remote_source, $upgrader, $hook_extra = array()) {
        if (is_wp_error($source)) {
            return $source;
        }
        if (empty($hook_extra['plugin']) || $hook_extra['plugin'] !== WPGUARD_CONNECTOR_BASENAME) {
            return $source;
        }

        $source_path = untrailingslashit((string) $source);
        $expected_directory = $this->get_slug();
        if (basename($source_path) === $expected_directory) {
            return trailingslashit($source_path);
        }
        // 7.4-safe "starts with <slug>-"
        if (strpos(basename($source_path), $expected_directory . '-') !== 0) {
            return $source;
        }

        $target = trailingslashit(dirname($source_path)) . $expected_directory;

        global $wp_filesystem;
        if ($wp_filesystem && $wp_filesystem->exists($target)) {
            $wp_filesystem->delete($target, true);
        } elseif (file_exists($target)) {
            $this->delete_directory($target);
        }

        if ($wp_filesystem && $wp_filesystem->move($source_path, $target, true)) {
            return trailingslashit($target);
        }
        if (@rename($source_path, $target)) {
            return trailingslashit($target);
        }

        return $source;
    }

    private function delete_directory($directory) {
        if (!is_dir($directory)) {
            return;
        }
        $items = scandir($directory);
        if (!is_array($items)) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $directory . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->delete_directory($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($directory);
    }

    public function clear_cache_after_update($upgrader, $hook_extra) {
        if (empty($hook_extra['action']) || $hook_extra['action'] !== 'update') {
            return;
        }
        if (empty($hook_extra['type']) || $hook_extra['type'] !== 'plugin') {
            return;
        }
        $plugins = isset($hook_extra['plugins'])
            ? (array) $hook_extra['plugins']
            : array(isset($hook_extra['plugin']) ? $hook_extra['plugin'] : '');
        if (in_array(WPGUARD_CONNECTOR_BASENAME, $plugins, true)) {
            $this->clear_cached_update_data();
        }
    }

    public function clear_cached_update_data() {
        delete_site_transient(self::CACHE_KEY);
    }

    /** Fetch (and cache) the remote version from the plugin header on GitHub. */
    private function get_remote_update_data($force = false) {
        if (!$force) {
            $cached = get_site_transient(self::CACHE_KEY);
            if (is_array($cached)) {
                return !empty($cached['version']) ? $cached : null;
            }
        }

        $response = wp_remote_get(
            $this->get_remote_plugin_file_url(),
            array(
                'timeout'     => 10,
                'redirection' => 3,
                'headers'     => array(
                    'Accept'     => 'text/plain',
                    'User-Agent' => 'WP-Guard-Connector/' . WPGUARD_CONNECTOR_VERSION . '; ' . home_url('/'),
                ),
            )
        );

        if (is_wp_error($response)) {
            $this->cache_failed_check();
            return null;
        }
        $status_code = (int) wp_remote_retrieve_response_code($response);
        if ($status_code < 200 || $status_code >= 300) {
            $this->cache_failed_check();
            return null;
        }

        $version = $this->parse_plugin_version((string) wp_remote_retrieve_body($response));
        if (!$version) {
            $this->cache_failed_check();
            return null;
        }

        $data = array(
            'version'      => $version,
            'package'      => $this->get_package_url(),
            'url'          => $this->get_repository_url(),
            'branch'       => $this->get_branch(),
            'last_checked' => time(),
        );
        set_site_transient(self::CACHE_KEY, $data, self::CACHE_TTL);

        return $data;
    }

    private function build_update_response($remote_data) {
        return (object) array(
            'id'           => $this->get_repository_url(),
            'slug'         => $this->get_slug(),
            'plugin'       => WPGUARD_CONNECTOR_BASENAME,
            'new_version'  => $remote_data['version'],
            'url'          => $remote_data['url'],
            'package'      => $remote_data['package'],
            'requires'     => '6.0',
            'requires_php' => '7.4',
            'tested'       => get_bloginfo('version'),
        );
    }

    private function parse_plugin_version($plugin_file_contents) {
        if (!preg_match('/^[ \t\/*#@]*Version:\s*([^\r\n]+)/mi', $plugin_file_contents, $matches)) {
            return null;
        }
        $version = trim($matches[1]);
        return $version !== '' ? $version : null;
    }

    private function should_force_check() {
        $force_check = isset($_GET['force-check']) ? sanitize_text_field(wp_unslash($_GET['force-check'])) : '';
        return is_admin() && current_user_can('update_plugins') && $force_check === '1';
    }

    private function cache_failed_check() {
        set_site_transient(self::CACHE_KEY, array('version' => '', 'last_checked' => time()), HOUR_IN_SECONDS);
    }

    private function get_slug() {
        return dirname(WPGUARD_CONNECTOR_BASENAME);
    }

    private function get_branch() {
        $branch = defined('WPGUARD_CONNECTOR_GITHUB_BRANCH') ? (string) WPGUARD_CONNECTOR_GITHUB_BRANCH : 'master';
        $branch = trim($branch);
        return $branch !== '' ? $branch : 'master';
    }

    private function get_remote_plugin_file_url() {
        return sprintf(
            'https://raw.githubusercontent.com/%s/%s/wp-guard-connector.php',
            WPGUARD_CONNECTOR_GITHUB,
            $this->get_url_branch()
        );
    }

    private function get_package_url() {
        return sprintf(
            'https://github.com/%s/archive/refs/heads/%s.zip',
            WPGUARD_CONNECTOR_GITHUB,
            $this->get_url_branch()
        );
    }

    private function get_repository_url() {
        return 'https://github.com/' . WPGUARD_CONNECTOR_GITHUB;
    }

    private function get_url_branch() {
        return implode('/', array_map('rawurlencode', explode('/', $this->get_branch())));
    }
}

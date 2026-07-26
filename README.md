# WP Guard Connector

WordPress plugin that connects a site to **[WP Guard](https://wpguard.top/)** — a
central hub for managing access across a fleet of WordPress sites. Pure PHP, no
dependencies, WordPress 6.0+.

**Project:** https://wpguard.top/

## What it does

- **Secure link to the portal** over an HMAC-signed, per-site channel — **both
  requests AND the portal's responses are signed** (an mTLS-equivalent). The plugin
  verifies each response with the per-site secret before acting on it, so a forged
  reply (e.g. a fake SSO redeem trying to log an attacker into wp-admin) is rejected.
- **Policy & user sync** — the portal is the source of truth; the plugin applies
  the desired login policy and manages users and their roles.
- **One-click SSO** into wp-admin from the portal.
- **Event streaming** — sign-ins, updates and plugin changes are reported to the
  portal's activity log; the plugin also reports the available WordPress core version
  so the portal can alert when a site can update.
- **Self-updates** from this GitHub repository.

## Connect a site

1. In the WP Guard portal, add the site and copy its one-time API key.
2. Install and activate this plugin.
3. Go to **Settings → WP Guard**, set the portal URL, paste the API key, and click
   **Connect**.

## Emergency off-switch

The site owner is never locked out. Add this to `wp-config.php` to fully disable
the connector and restore standard WordPress login:

```php
define( 'WPGUARD_DISABLE', true );
```

## Response-signature enforcement

The plugin verifies the portal's response signatures by default and refuses replies
that are unsigned or forged. As an **emergency valve only** (e.g. a portal-side rollback
that temporarily ships unsigned replies), you may accept unsigned responses with:

```php
define( 'WPGUARD_REQUIRE_RESP_SIG', false );
```

Leave this ON (the default) in normal operation.

## License

GPL-2.0-or-later

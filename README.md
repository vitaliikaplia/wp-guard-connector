# WP Guard Connector

WordPress plugin that connects a site to **[WP Guard](https://wpguard.top/)** — a
central hub for managing access across a fleet of WordPress sites. Pure PHP, no
dependencies, WordPress 6.0+.

**Project:** https://wpguard.top/

## What it does

- **Secure link to the portal** over an HMAC-signed, per-site channel.
- **Policy & user sync** — the portal is the source of truth; the plugin applies
  the desired login policy and manages users and their roles.
- **One-click SSO** into wp-admin from the portal.
- **Event streaming** — sign-ins, updates and plugin changes are reported to the
  portal's activity log.
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

## License

GPL-2.0-or-later

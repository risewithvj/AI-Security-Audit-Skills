<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# WordPress checklist

Auto-selected when `wordpress` is detected. Hunt in **custom and modified themes and plugins**; treat WordPress core (`wp-admin/`, `wp-includes/`) and well-known public plugins as dependencies (record versions, do not re-audit their internals). Every item is a lead to verify from source, not a finding.

## 1. Exposed files in the web root (highest signal, often missed)
The document root is `/var/www/html` (or the site root). Anything there is served to anonymous visitors.
- **Backup archives**: `*.zip`, `*.tar`, `*.tar.gz`, `*.sql`, `*.sql.gz` in the docroot, `wp-content/`, `wp-content/uploads/`, `wp-content/wpvividbackups/`, `*/updraft/`. A full-site or DB backup here is a one-request full breach (source, secrets, password hashes, data). Confirm the file exists and that no `.htaccess`/server rule blocks it.
- **Logs**: `error_log`, `debug.log` (`wp-content/debug.log`), `*.log` — path and error disclosure; sometimes data.
- **Editor leftovers**: `*.php-<date>`, `*.php.bak`, `*.bak`, `*.old`, `*.orig`, `*.save`, `*.swp`, `*~`, `*.php~`. A non-`.php` final extension is served as **plain-text source**.
- **VCS / config**: `.git/`, `.env`, `wp-config.php.bak`, `wp-config-sample.php` left with real values.

## 2. wp-config.php hardening
- `WP_DEBUG` / `WP_DEBUG_DISPLAY` true in production (errors leak to visitors); `WP_DEBUG_LOG` writing a web-readable `debug.log`.
- `DISALLOW_FILE_EDIT` not set to true (admin theme/plugin editor allows code execution from the dashboard).
- Auth keys and salts are the sample placeholders or committed/known values (should be unique, from the salt API).
- `FORCE_SSL_ADMIN` not set; default `wp_` table prefix (minor, aids blind SQLi).
- Database credentials or secrets hardcoded here or in `docker-compose.yml`/`.env` committed to the repo.

## 3. Custom theme / plugin code (where the bundled PHP rules point)
- `$wpdb->query/get_results/get_var` built from `$_GET/$_POST/$_REQUEST` without `$wpdb->prepare()` — SQL injection.
- `echo`/`print` of request data without `esc_html/esc_attr/esc_url/wp_kses/sanitize_*` — reflected/stored XSS; `the_content` filters and shortcode output.
- **AJAX**: `wp_ajax_nopriv_<x>` (and `wp_ajax_<x>`) handlers must call `check_ajax_referer`/`wp_verify_nonce` **and** a `current_user_can()` capability check before acting.
- **REST**: `register_rest_route` with `permission_callback => '__return_true'` on write methods (POST/PUT/PATCH/DELETE) = unauthenticated write. Confirm each is meant to be public.
- `unserialize`/`maybe_unserialize`, `include`/`require`, `eval`/`create_function`/`preg_replace /e`, `system`/`exec`, `extract()`, `file_get_contents`/`wp_remote_get` on request data.
- File upload: `move_uploaded_file`/`wp_handle_upload` without an allow-list of types; PHP execution allowed in `wp-content/uploads`.
- Capability checks: `is_admin()` is NOT an auth check (it only means "admin area"); use `current_user_can()`.

## 4. Platform exposure
- **XML-RPC** (`xmlrpc.php`) enabled — brute-force amplification (`system.multicall`) and pingback SSRF; confirm it is disabled or filtered.
- **User enumeration**: `/?author=1` redirects to the author slug; `/wp-json/wp/v2/users` lists usernames. Confirm these are blocked if usernames must stay private.
- **REST/oEmbed** information disclosure; directory listing on `wp-content/uploads`.
- `readme.html` / `wp-includes/version.php` exposing the exact WP version.

## 5. Components (dependency posture — see `aisa.py wpvulns`)
- Record each theme and plugin **slug and version** (plugin `readme.txt` `Stable tag`, theme `style.css` `Version:`). List them in the dependency table.
- Flag **nulled/pirated** premium plugins (no valid update channel), abandoned plugins (no update in years), and known-critical ones to check (Slider Revolution, old Elementor, File Manager, etc.). WordPress plugin CVEs are not in OSV/Trivy — check WPScan/Patchstack. If `WPSCAN_API_TOKEN` is set, `aisa.py wpvulns --run <run>` queries it; otherwise the report lists versions as "not checked: no WordPress vulnerability feed".

## 6. Deployment (docker-compose / server)
- Hardcoded `MYSQL_ROOT_PASSWORD`/`WORDPRESS_DB_PASSWORD` in `docker-compose.yml`; weak/predictable values; committed `.env`.
- **phpMyAdmin / adminer** service exposed on a published port — a direct DB console; confirm it is not reachable in production.
- Database port (3306/5432) published to the host; `WORDPRESS_DEBUG` enabled.

## What never passes (WordPress-specific)
- A plugin/theme version with no demonstrated reachable issue, reported as a vulnerability — it is a dependency note until WPScan/Patchstack confirms and reachability is shown.
- "XML-RPC enabled" or "user enumeration" with no stated concrete impact — report as hardening unless chained to something real.
- A nonce/capability check that exists a few lines away or in a shared helper — trace before claiming "no nonce".

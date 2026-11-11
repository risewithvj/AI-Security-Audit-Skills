<?php
// AI-Security-Audit-Skills test fixture | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
// Planted PHP/WordPress issues for the bundled aisa-php rules, with negative cases
// that must NOT fire. Not a runnable plugin.

global $wpdb;

// POSITIVE: wpdb-unprepared (interpolation and concatenation)
$id = $_GET['id'];
$wpdb->query("DELETE FROM wp_things WHERE id = {$id}");
$rows = $wpdb->get_results("SELECT * FROM wp_things WHERE name = '" . $_GET['n'] . "'");
// NEGATIVE: prepared statement must NOT fire
$safe = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_things WHERE id = %d", $id));

// POSITIVE: echo-request-xss
echo $_GET['q'];
print $_POST['x'];
echo "Hello " . $_REQUEST['name'];
// NEGATIVE: escaped output must NOT fire
echo esc_html($_GET['q']);
echo sanitize_text_field($_POST['x']);

// POSITIVE: unserialize-request
$obj = unserialize($_COOKIE['data']);
$o2 = maybe_unserialize($_POST['blob']);
// NEGATIVE: json_decode must NOT fire
$json = json_decode($_POST['blob'], true);

// POSITIVE: include-request
include($_GET['page']);
require_once($_REQUEST['tpl']);
// NEGATIVE: constant path must NOT fire
include(__DIR__ . '/header.php');

// POSITIVE: dynamic-eval
eval($code);
create_function('$a', $body);
// NEGATIVE: call_user_func must NOT fire
call_user_func('strtoupper', 'x');

// POSITIVE: exec-request
system("ping " . $_GET['host']);
shell_exec("ls " . $_POST['dir']);
// NEGATIVE: static command must NOT fire
system("uptime");

// POSITIVE: extract-request
extract($_REQUEST);
// NEGATIVE: extract of a safe parsed array must NOT fire
extract($parsed_defaults);

// POSITIVE: ssrf-request-url
$body = wp_remote_get($_GET['url']);
$data = file_get_contents($_REQUEST['feed']);
// NEGATIVE: constant URL must NOT fire
$ok = wp_remote_get('https://api.example.com/health');

// POSITIVE: base64-eval backdoor
eval(base64_decode($payload));
eval(gzinflate($blob));

// POSITIVE: upload-no-type-check
move_uploaded_file($_FILES['f']['tmp_name'], $dest);

// POSITIVE: rest-permission-open
add_action('rest_api_init', function () {
    register_rest_route('myplugin/v1', '/save', array(
        'methods'             => 'POST',
        'callback'            => 'myplugin_save',
        'permission_callback' => '__return_true',
    ));
});
// NEGATIVE: a real permission check must NOT fire
register_rest_route('myplugin/v1', '/read', array(
    'methods'             => 'GET',
    'callback'            => 'myplugin_read',
    'permission_callback' => 'myplugin_can_read',
));

// POSITIVE: ajax-nopriv-no-nonce
add_action('wp_ajax_nopriv_myplugin_do', 'myplugin_do');

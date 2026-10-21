<?php
// Test script: prints $_POST, $_FILES (with content md5) and selected $_SERVER as JSON.
header('Content-Type: application/json; charset=utf-8');
if (isset($_GET['status'])) { http_response_code((int)$_GET['status']); }
if (isset($_GET['sleep'])) { usleep((int)$_GET['sleep'] * 1000); }
if (isset($_GET['cookie'])) { setcookie('test', 'v=1; x', time()+60, '/'); header('X-Custom: ěšč'); }
function files_md5($entry) {
    if (!isset($entry['tmp_name'])) return $entry;
    if (is_array($entry['tmp_name'])) {
        $out = [];
        foreach ($entry['tmp_name'] as $k => $tmp) {
            $out[$k] = ['name' => $entry['name'][$k], 'type' => $entry['type'][$k], 'size' => $entry['size'][$k],
                'error' => $entry['error'][$k], 'md5' => ($entry['error'][$k] === 0 && $tmp !== '') ? md5_file($tmp) : null];
        }
        return $out;
    }
    return ['name' => $entry['name'], 'type' => $entry['type'], 'size' => $entry['size'], 'error' => $entry['error'],
        'md5' => ($entry['error'] === 0 && $entry['tmp_name'] !== '') ? md5_file($entry['tmp_name']) : null];
}
$files = [];
foreach ($_FILES as $k => $v) { $files[$k] = files_md5($v); }
$keys = ['REMOTE_ADDR','HTTPS','SERVER_PORT','SERVER_PROTOCOL','REQUEST_METHOD','HTTP_HOST','REQUEST_URI','QUERY_STRING',
    'CONTENT_LENGTH','HTTP_X_FORWARDED_FOR','HTTP_X_FORWARDED_PROTO','HTTP_CF_CONNECTING_IP','HTTP_X_GUARD_ORIG_IP',
    'HTTP_USER_AGENT','HTTP_COOKIE','HTTP_ACCEPT','HTTP_ACCEPT_ENCODING','HTTP_X_CUSTOM','HTTP_AUTHORIZATION'];
$server = [];
foreach ($keys as $k) { if (isset($_SERVER[$k])) $server[$k] = $_SERVER[$k]; }
$server['CONTENT_TYPE_PREFIX'] = explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0];
$server['HAS_GUARD_TOKEN'] = isset($_SERVER['HTTP_X_MULTIPART_GUARD']);
$input = file_get_contents('php://input');
echo json_encode(['post' => $_POST, 'files' => $files, 'server' => $server,
    'input_len' => strlen($input), 'input_md5' => md5($input),
    'upload_progress_enabled' => ini_get('session.upload_progress.enabled')],
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
if (isset($_GET['big'])) { echo "\n", str_repeat("0123456789abcdef", 65536 * (int)$_GET['big']); }

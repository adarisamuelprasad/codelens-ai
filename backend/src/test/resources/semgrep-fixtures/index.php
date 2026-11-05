<?php
$id = $_GET['id'];
// codelens-expect: SQL_INJECTION
$r = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
// codelens-expect: COMMAND_INJECTION
system("ping -c 1 " . $_GET['host']);
system("uptime");
system("ping -c 1 " . escapeshellarg($_GET['host']));
// codelens-expect: UNSAFE_HTML
echo "Hello " . $_GET['name'];
echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES);
// codelens-expect: INSECURE_DESERIALIZATION
$obj = unserialize($_COOKIE['state']);
$data = json_decode($_COOKIE['state'], true);
// codelens-expect: CODE_INJECTION
eval($_POST['code']);
// codelens-expect: TLS_VERIFY_DISABLED
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
// codelens-expect: PERMISSIVE_CORS
header("Access-Control-Allow-Origin: *");
// codelens-expect: SWALLOWED_EXCEPTION
try {
    risky();
} catch (Exception $e) {
}

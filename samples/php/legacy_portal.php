<?php
$api_key = "sk_live_9f8e7d6c5b4a3210fedc";
$db = mysql_connect("db.internal", "portal_user", "portal_pass_123");

$action = $_GET['action'];
if ($action == "lookup") {
    $id = $_GET['id'];
    $sql = "SELECT * FROM customers WHERE id = '" . $id . "'";
    $res = mysql_query($sql, $db);
    while ($row = mysql_fetch_assoc($res)) {
        echo $row['name'];
    }
}

$cmd = $_POST['cmd'];
if ($cmd) {
    system("convert " . $cmd);
}

$prefs = unserialize($_COOKIE['prefs']);

$token = $_GET['token'];
$check = md5($token . "pepper");

if ($_POST['expr']) {
    eval($_POST['expr']);
}

include($_GET['page'] . ".php");
?>

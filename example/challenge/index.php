<?php

require 'config.php'; // $flag $key


function encrypt($data, $key) {
    $length = openssl_cipher_iv_length('aes-256-cbc');
    $iv = openssl_random_pseudo_bytes($length);
    $cipher = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $cipher);
}

function decrypt($data, $key) {
    $length = openssl_cipher_iv_length('aes-256-cbc');
    $data = base64_decode($data);
    $iv = substr($data, 0, $length);
    $cipher = substr($data, $length);
    return openssl_decrypt($cipher, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
}


if ($name = @$_POST['name']) {
    $data = serialize([
        'name' => $name,
        'can_see_the_flag' => FALSE,
    ]);
    $session = encrypt($data, $key);
    $_COOKIE['session'] = $session;
    setcookie('session', $session);
    header('Location: .');
    exit;
}

$showFlag = FALSE;
$name = NULL;

if ($session = @$_COOKIE['session']) {
    $data = decrypt($session, $key);
    if ($data === FALSE) {
        die('session error');
    }
    $data = unserialize($data);
    $name = $data['name'];
    $showFlag = $data['can_see_the_flag'];
}


echo '<title>Find the FLAG</title>';
if ($name) {
    echo "<h1>Hi, $name.</h1>";
    if ($showFlag) {
        echo "This is your flag: <b>$flag</b>";
    } else {
        echo "You cannot see the flag!";
    }
} else {
    echo '<h1>Tell me your name!</h1>';
    echo '<form method="post">';
    echo   '<input type="text" name="name" placeholder="name">';
    echo   '&nbsp;';
    echo   '<input type="submit" value="Go">';
    echo '</form>';
}

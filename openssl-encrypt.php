<?php

$plaintext = 'This is my text';

function Encrypt_decrypt_aes_128($string, $action='encrypt')
{
    $output = false;
    $encrypt_method = "AES-256-CBC";
    $secret_key = 'hVmYq3t6w9z$C&F)';
    $secret_iv = 'gUkXp2s5';
    // hash
    $key = hash('sha256', $secret_key);
    // iv - encrypt method AES-256-CBC expects 16 bytes
    $iv = substr(hash('sha256', $secret_iv), 0, 16);
    if ( $action == 'encrypt' ) {
        $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
        $output = base64_encode($output);
    } else if( $action == 'decrypt' ) {
        $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
    }
    return $output;
}

$encrypted = Encrypt_decrypt_aes_128($plaintext);
$decrypt = Encrypt_decrypt_aes_128($plaintext, 'decrypt');

print "Plain: $plaintext" . PHP_EOL;
print "Encrypted: $encrypted" . PHP_EOL;

print '-------------------------------' . PHP_EOL;

print "Decrypted: $decrypt" . PHP_EOL;
<?php

/**
 * @param string $text log text with datetime to stdout
 */
function logger($text){
    print date('[Y-m-d H:i:s] - ') . $text . PHP_EOL;
}

/**
 * Get secure random string
 * @param int $length length of string
 * @return string random string
 */
function getSecureRandom($length = 32)
{
    $randomString = openssl_random_pseudo_bytes($length, $isStrong);
    if (!$isStrong) {
        throw new RuntimeException('Cannot generate secure random bytes');
    }
    return $randomString;
}

/**
 * Class HandshakeHash smart class to manage handshake hash
 */
class HandshakeHash{
    public $data = '';

    public function __construct($defaultValue = '')
    {
        $this->data = $defaultValue;
    }

    /**
     * @param string $data set hash value
     */
    public function setHash($data){
        $this->data = $data;
    }

    /**
     * @param string $data update hash value
     */
    public function update($data){
        $this->data = hash('sha256', $this->data . $data, true);
    }

    /**
     * @return string get hash value
     */
    public function getHash(){
        return $this->data;
    }
}

/**
 * Key derivation
 * @param $key
 * @param string $digest
 * @param null $salt
 * @param null $length
 * @param string $info
 * @return bool|string
 */
function hkdf($key, $digest = 'sha512', $salt = NULL, $length = NULL, $info = '')
{
    if ( ! in_array($digest, array('sha224', 'sha256', 'sha384', 'sha512'), TRUE))
    {
        return FALSE;
    }

    $digest_length = substr($digest, 3) / 8;
    if (empty($length) OR ! is_int($length))
    {
        $length = $digest_length;
    }
    elseif ($length > (255 * $digest_length))
    {
        return FALSE;
    }

    isset($salt) OR $salt = str_repeat("\0", substr($digest, 3) / 8);

    $prk = hash_hmac($digest, $key, $salt, TRUE);
    $key = '';
    for ($key_block = '', $block_index = 1; strlen($key) < $length; $block_index++)
    {
        $key_block = hash_hmac($digest, $key_block.$info.chr($block_index), $prk, TRUE);
        $key .= $key_block;
    }

    return substr($key, 0, $length);
}
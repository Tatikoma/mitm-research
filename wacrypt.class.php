<?php
abstract class WACrypt{
    /**
     * @var string Protocol version header
     */
    public $protocolVersion = "\x57\x41\x02\x00"; // WA20
    /**
     * Noise_XX_25519_AESGCM_SHA256  in this case
     * @var string some string using during Noise handshake.
     */
    public $handshakeName = "\x4E\x6F\x69\x73\x65\x5F\x58\x58\x5F\x32\x35\x35\x31\x39\x5F\x41\x45\x53\x47\x43\x4D\x5F\x53\x48\x41\x32\x35\x36\x00\x00\x00\x00";

    /**
     * @var HandshakeHash chain hash
     */
    public $handshakeChain;
    /**
     * @var string AES key
     */
    public $handshakeAES;
    /**
     * @var string nonce
     */
    public $handshakeNonce;

    /**
     * @var string write key
     */
    public $writeKey;
    /**
     * @var string read key
     */
    public $readKey;
    /**
     * @var string write nonce
     */
    public $writeNonce;
    /**
     * @var string read nonce
     */
    public $readNonce;

    /**
     * @var string curve private key
     */
    public $curvePrivate;
    /**
     * @var string curve public key
     */
    public $curvePublic;

    /**
     * @var string chain key
     */
    public $chainKey;

    /**
     * @var string ephemeral private key
     */
    public $ephemeralPrivateKey;
    /**
     * @var string ephemeral public key
     */
    public $ephemeralPublicKey;
    /**
     * @var string shared public key
     */
    public $sharedPublicKey;
    /**
     * @var string shared curve key
     */
    public $sharedCurveKey;
    /**
     * @var string chat static public key & cert, used during Noise handshake
     */
    public $chatStaticCert;

    /**
     * Encrypt stream
     * @param string $payload binary data
     * @param bool $compress whether to compress data
     * @return string encrypted data
     */
    public function encryptStream($payload, $compress = false){
        $iv = pack('NNN', 0, 0, $this->writeNonce);

        $flags = 0x00;
        if($compress){
            $flags |= 0x02;
            $payload = zlib_encode($payload, ZLIB_ENCODING_DEFLATE, 1);
        }

        $payload = pack('C', $flags) . $payload;

        $cipher = Crypto\Cipher::aes(Crypto\Cipher::MODE_GCM, 256);

        $result = $cipher->encrypt($payload, $this->writeKey, $iv);
        $result .= $cipher->getTag();

        $this->writeNonce++;

        return $result;
    }

    /**
     * Decrypt stream
     * @param string $payload binary data
     * @return string decrypted data
     */
    public function decryptStream($payload){
        $iv = pack('NNN', 0, 0, $this->readNonce);

        $data = substr($payload, 0, -16);
        $tag = substr($payload, -16);

        $cipher = Crypto\Cipher::aes(Crypto\Cipher::MODE_GCM, 256);
        $cipher->setTag($tag);
        $result = $cipher->decrypt($data, $this->readKey, $iv);

        $this->readNonce++;

        $flags = ord($result[0]);

        $result = substr($result, 1);

        if($flags & 0x02 === 0x02){
            $result = zlib_decode($result);
        }

        return $result;
    }

    /**
     * Encrypt handshake
     * @param string $payload binary data
     * @return string encrypted data
     */
    public function handshakeEncrypt($payload){
        switch(true){
            case $this instanceof Client:
                $iv = pack('NNN', 0, 0, $this->handshakeNonce);
                break;
            case $this instanceof Server:
                $iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
                break;
            default:
                throw new RuntimeException('Incorrect usage');
                break;
        }


        $cipher = Crypto\Cipher::aes(Crypto\Cipher::MODE_GCM, 256);
        $cipher->setAAD($this->handshakeChain->getHash());

        $result = $cipher->encrypt($payload, $this->handshakeAES, $iv);
        $result .= $cipher->getTag();

        $this->handshakeChain->update($result);

        if($this instanceof Server){
            $this->handshakeNonce++;
        }

        return $result;
    }

    /**
     * Decrypt handshake
     * @param string $payload binary data
     * @return mixed decrypted data
     */
    public function handshakeDecrypt($payload){
        switch(true){
            case $this instanceof Client:
                $iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
                break;
            case $this instanceof Server:
                $iv = pack('NNN', 0, 0, $this->handshakeNonce);
                break;
            default:
                throw new RuntimeException('Incorrect usage');
                break;
        }

        $data = substr($payload, 0, -16);
        $tag = substr($payload, -16);

        $cipher = Crypto\Cipher::aes(Crypto\Cipher::MODE_GCM, 256);
        $cipher->setTag($tag);
        $cipher->setAAD($this->handshakeChain->getHash());
        $result = $cipher->decrypt($data, $this->handshakeAES, $iv);

        $this->handshakeChain->update($payload);

        if($this instanceof Client){
            $this->handshakeNonce++;
        }

        return $result;
    }

    /**
     * Handshake set shared key
     * @param string $private private key
     * @param string $public public key
     */
    public function handshakeSetKey($private, $public){
        $agreement = curve25519_shared($private, $public);

        $hkdf = hkdf($agreement, 'sha256', $this->chainKey, 64);
        $this->chainKey = substr($hkdf, 0, 32);
        $this->handshakeAES = substr($hkdf, 32, 32);
        $this->handshakeNonce = 0;
    }
}
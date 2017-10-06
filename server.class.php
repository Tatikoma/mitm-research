<?php

require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/wacrypt.class.php';

/**
 * Class Server MITM server to emulate WhatsApp server
 */
class Server extends WACrypt {
    /**
     * Connection state: client_hello
     */
    const CONNECTION_HELLO = 1;
    /**
     * Connection state: client_finish
     */
    const CONNECTION_FINISH = 2;
    /**
     * Connection state: client logged, handshake done
     */
    const CONNECTION_LOGGED = 3;

    /**
     * @var string data buffer received from client
     */
    public $buffer = '';
    /**
     * @var bool flag if protocol version already present in stream
     */
    public $isProtocolVersionPresent = false;
    /**
     * @var int current state of connection
     */
    public $connectionState = self::CONNECTION_HELLO;

    /**
     * @var resource client connection
     */
    public $clientConnectionHandle;

    /**
     * @var Client client used to connect to real server
     */
    public $client;
    /**
     * @var string client username (phone number)
     */
    public $username;
    /**
     * @var string client password (cck.dat)
     */
    public $password;

    /**
     * Server constructor with options
     * @param array $options options
     */
    public function __construct($options)
    {
        $this->client = $options['client'];
        $this->username = $options['username'];
        $this->password = $options['password'];
        $this->chatStaticCert = "\x0a\x4f\x08\x01\x12\x11\x57\x68\x61\x74\x73\x41\x70\x70\x4c\x6f\x6e\x67\x54\x65\x72\x6d\x31\x22\x16\x43\x68\x61\x74\x20\x53\x74\x61\x74\x69\x63\x20\x50\x75\x62\x6c\x69\x63\x20\x4b\x65\x79\x2a\x20\xf3\xa4\xb1\x5f\x62\x4a\xa0\xc7\x25\x94\x19\xf3\x78\xf6\x48\xba\xdd\xcd\xf3\x56\xce\xb0\xe2\x89\x12\xaa\x9e\xa4\x70\x06\xa1\x5c\x12\x40\x0c\x8b\x88\x3e\xf3\xe8\x20\x08\xff\x2f\x2b\x88\x4e\xdd\x75\x39\x59\x7d\xa6\x48\x40\x52\x45\x62\xe0\x76\x4a\x04\x63\xe7\xfc\xb2\x14\x9c\x10\xec\x2d\x82\x97\xa6\xf5\x65\xde\x85\x4b\xa4\xcf\x1f\x50\x4c\x5f\xba\x8d\x5e\xbd\xf4\x9c\x53\xd4\x5f\xbb\x49\x5f\x81";
    }

    /**
     * Listen socket server
     * @param string $listenSocket socket descr
     * @throws Exception
     */
    public function listen($listenSocket){
        $sock = stream_socket_server($listenSocket, $errno, $errstr);
        if (!$sock) {
            echo "$errstr ($errno)<br />\n";
            exit;
        }
        while(1) {
            logger('Server listen at ' . $listenSocket);

            do {
                $ip = @stream_socket_accept($sock);
            } while (!$ip);

            stream_set_blocking($ip, 0);
            $this->clientConnectionHandle = $ip;
            logger('Got connection');

            while (true) {
                if(null !== $this->client){
                    $this->client->tick();
                }

                $data = fread($ip, 0xFFFF);
                try {
                    $this->parseBuffer($data);
                } catch (Exception $e) {
                    logger('Exception while parsing stream: ' . $e->getMessage());
                    $this->buffer = '';
                    $this->isProtocolVersionPresent = false;
                    $this->connectionState = self::CONNECTION_HELLO;
                    fclose($ip);
                    continue 2;
                }

                usleep(100000);
            }
            fclose($ip);
        }
        fclose($sock);
    }

    /**
     * Parse data from client
     * @param string $buffer binary data
     * @throws RuntimeException
     */
    public function parseBuffer($buffer){
        $this->buffer .= $buffer;

        if(!$this->isProtocolVersionPresent){
            if(strlen($this->buffer) < strlen($this->protocolVersion)){
                return;
            }
            if(strpos($this->buffer, $this->protocolVersion) === 0){
                $this->buffer = substr($this->buffer, strlen($this->protocolVersion));
                $this->isProtocolVersionPresent = true;
            }
            else {
                throw new RuntimeException('Protocol version header not found');
            }
        }

        if(strlen($this->buffer) < 3){
            return;
        }

        $header = unpack('Ctype/nlength', substr($this->buffer, 0, 3));
        while(strlen($this->buffer) >= $header['length'] + 3){
            $packet = substr($this->buffer, 3, $header['length']);
            $this->buffer = substr($this->buffer, 3 + $header['length']);
            $this->onPacket($packet);
        }
    }


    /**
     * Handle packets from client
     * @param string $packet binary data
     * @throws RuntimeException
     */
    public function onPacket($packet){
        logger('Client -> MITM');
        logger(bin2hex($packet));
        switch($this->connectionState){
            case self::CONNECTION_HELLO:
                // verify data
                if(strpos($packet, "\x12\x22\x0A\x20") !== 0){
                    throw new RuntimeException('Received unknown packet at client_hello');
                }

                // generate keys
                $this->curvePrivate = curve25519_private(getSecureRandom(32));
                $this->curvePublic = curve25519_public($this->curvePrivate);

                $this->sharedPublicKey = substr($packet, 4);

                $this->ephemeralPrivateKey = curve25519_private(getSecureRandom(32));
                $this->ephemeralPublicKey = curve25519_public($this->ephemeralPrivateKey);

                $this->chainKey = $this->handshakeName;

                $this->handshakeChain = new HandshakeHash();
                $this->handshakeChain->setHash($this->handshakeName);
                $this->handshakeChain->update($this->protocolVersion);
                $this->handshakeChain->update($this->sharedPublicKey);
                $this->handshakeChain->update($this->ephemeralPublicKey);

                $this->handshakeSetKey($this->ephemeralPrivateKey, $this->sharedPublicKey);

                $encryptedKey = $this->handshakeEncrypt($this->curvePublic);

                $this->handshakeSetKey($this->curvePrivate, $this->sharedPublicKey);
                $encryptedCert = $this->handshakeEncrypt($this->chatStaticCert);

                // produce response
                $packet = "\x1a\xfa\x01\x0a\x20"
                    . $this->ephemeralPublicKey
                    . "\x12\x30"
                    . $encryptedKey
                    . "\x1a\xa3\x01"
                    . $encryptedCert;
                $packet = pack('Cn', 0, strlen($packet)) . $packet;

                $this->sendPacket($packet);

                $this->connectionState = self::CONNECTION_FINISH;
                break;
            case self::CONNECTION_FINISH:
                // decrypt client data
                $sizeCurvePublic = ord($packet[4]);
                $sizeClientPayload = ord($packet[5 + $sizeCurvePublic + 1]);
                $clientCurvePublic = substr($packet, 5, $sizeCurvePublic);
                $clientPayload = substr($packet, 5 + $sizeCurvePublic + 2, $sizeClientPayload);

                $decryptedClientCurve = $this->handshakeDecrypt($clientCurvePublic);

                $this->handshakeSetKey($this->ephemeralPrivateKey, $decryptedClientCurve);
                $decryptedPayload = $this->handshakeDecrypt($clientPayload);

                logger('Decrypted payload: ' . bin2hex($decryptedPayload));

                $this->connectionState = self::CONNECTION_LOGGED;

                // set keys
                $hkdf = hkdf('', 'sha256', $this->chainKey, 64);
                $this->writeKey = substr($hkdf, 32, 32);
                $this->readKey = substr($hkdf, 0, 32);
                $this->writeNonce = 0;
                $this->readNonce = 0;

                /** @noinspection ExceptionsAnnotatingAndHandlingInspection */
                $this->client->connect($this->username, $this->password);

                $this->client->onPacket(function($binary){
                    $encrypt = $this->encryptStream($binary);
                    $packet = pack('Cn', 0, strlen($encrypt)) . $encrypt;
                    $this->sendPacket($packet);
                });

                break;
            case self::CONNECTION_LOGGED:
                $decrypted = $this->decryptStream($packet);

                /** @noinspection ExceptionsAnnotatingAndHandlingInspection */
                $packet = $this->client->writeStream($decrypted);
                /** @noinspection ExceptionsAnnotatingAndHandlingInspection */
                $this->client->sendPacket($packet);
                break;
        }
    }

    /**
     * Send binary packet to client
     * @param string $packet
     */
    public function sendPacket($packet){
        logger('MITM -> Client');
        logger(bin2hex($packet));
        fwrite($this->clientConnectionHandle, $packet);
    }
}
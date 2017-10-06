<?php
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/tokenstaticmap.class.php';
require_once __DIR__ . '/wacrypt.class.php';

class Client extends WACrypt {
    public $serverAddr = '';

    public function __construct(array $options)
    {
        if(isset($options['server_addr'])){
            $this->serverAddr = $options['server_addr'];
        }
    }
    /**
     * @var string read buffer from server
     */
    public $readBuffer;

    /**
     * @var resource tcp-socket to server
     */
    public $socket;

    /**
     * @var string client username (phone number)
     */
    public $username;
    /**
     * @var string client password (cck.dat)
     */
    public $password;
    /**
     * @var callable[] list of packet handlers
     */
    public $packetHandler = [];
    /**
     * @var string server hello packet received during handshake
     */
    public $serverHello;
    /**
     * @var bool whether handshake is done and client is logged in
     */
    public $isLogged = false;
    /**
     * @var string Version of application to be sent to server
     */
    public $appVersion = '2.17.52';

    /**
     * Begin connection to server
     * @param string $username client username (phone number)
     * @param string $password client password (cck.dat)
     * @throws RuntimeException
     */
    public function connect($username, $password){
        $serverAddr = $this->serverAddr;
        if(!$serverAddr){
            $serverAddr = $this->getServerAddr();
        }

        $this->socket = @fsockopen($serverAddr, 443, $errno, $errstr);
        if($this->socket === false){
            throw new RuntimeException(strtr('Connection to server :ip failed: (:errno) :errstr', array(
                ':ip' => $serverAddr,
                ':errno' => $errno,
                ':errstr' => $errstr,
            )));
        }


        $this->username = $username;
        $this->password = $password;

        $this->sendClientHello();
        $this->sendClientFinish();
    }

    /**
     * tick function to receive new data from server
     * @throws Exception
     */
    public function tick(){

        if(!is_resource($this->socket)){
            return;
        }
        stream_set_blocking($this->socket, 0);
        do{
            $read = fread($this->socket, 0xFFFF);
            $this->readBuffer .= $read;
        }
        while(strlen($read) > 0);

        if(strlen($this->readBuffer) < 3){
            return;
        }

        $streamHeader = unpack('N', "\x00" . substr($this->readBuffer, 0, 3))[1];
        $streamLength = $streamHeader & 0x0FFFFF;

        while(strlen($this->readBuffer) >= $streamLength + 3){
            $packet = substr($this->readBuffer, 3, $streamLength);
            $this->readBuffer = substr($this->readBuffer, $streamLength + 3);

            if($this->isLogged){
                $packet = $this->decryptStream($packet);
            }
            logger('Server -> MITM');
            logger(bin2hex($packet));

            if(!$this->isLogged) {
                $this->serverHello = $packet;
            }
            else{
                $node = $this->parseNode($packet);
                $this->showNode($node);
                foreach($this->packetHandler as $handler){
                    $handler($packet);
                }
            }

            if(strlen($this->readBuffer) < 3){
                break;
            }
            $streamHeader = unpack('N', "\x00" . substr($this->readBuffer, 0, 3))[1];
            $streamLength = $streamHeader & 0x0FFFFF;
        }
    }

    /**
     * Send client_hello NoiseHandshake
     */
    public function sendClientHello(){
        $this->curvePrivate = $this->password;
        $this->curvePublic = curve25519_public($this->curvePrivate);
        $this->handshakeChain = new HandshakeHash($this->handshakeName);
        $this->chainKey = $this->handshakeName;

        $packet = $this->protocolVersion;
        $this->sendPacket($packet);
        $this->handshakeChain->update($packet);

        $this->ephemeralPrivateKey = getSecureRandom(32);
        $this->ephemeralPublicKey = curve25519_public($this->ephemeralPrivateKey);
        $this->handshakeChain->update($this->ephemeralPublicKey);

        $packet = "\x12\x22\x0a" . pack('C', strlen($this->ephemeralPublicKey)) . $this->ephemeralPublicKey;
        $packet = $this->writeStream($packet);
        $this->sendPacket($packet);
    }

    /**
     * Send client_finish NoiseHandshake
     */
    public function sendClientFinish(){
        while(empty($this->serverHello)){
            $this->tick();
            usleep(100000);
        }

        $packet = $this->serverHello;

        $serverHelloPayload = substr($packet, 90, 163);
        $serverHelloStaticP = substr($packet, 39, 48);
        $this->sharedPublicKey = substr($packet, 5, 32);

        $this->handshakeChain->update($this->sharedPublicKey);

        $this->handshakeSetKey($this->ephemeralPrivateKey, $this->sharedPublicKey);
        $this->sharedCurveKey = $this->handshakeDecrypt($serverHelloStaticP);


        $this->handshakeSetKey($this->ephemeralPrivateKey, $this->sharedCurveKey);
        $this->chatStaticCert = $this->handshakeDecrypt($serverHelloPayload);

        $encryptedClientCurvePublic = $this->handshakeEncrypt($this->curvePublic);

        $this->handshakeSetKey($this->curvePrivate, $this->sharedPublicKey);

        $clientPayload = "\x08";

        // process phone number for payload
        $user4low = $this->username & 0xFFFFFFFF;
        $user4high = $this->username >> 32;
        $stop = false;
        if($user4low < 0x80){
            $stop = true;
        }
        while(!$stop){
            $clientPayload .= chr($user4low & 0xFF | 0x80);
            if($user4low < 0x4000){
                $stop = true;
            }
            $user4low = ($user4low >> 7) | (($user4high << 25) & 0xFFFFFFFF);
            $user4low &= 0xFFFFFFFF;
            if($user4high > 0){
                $stop = false;
            }
            $user4high >>= 7;
        }

        $version = explode('.', $this->appVersion);

        $clientPayload .= chr($user4low);

        $clientPayload .= "\x12\x01\x20"; // password
        $clientPayload .= "\x18"; // passive
        $clientPayload .= "\x01"; // client features
        $clientPayload .= "\x2a\x5b"; // user agent
        $clientPayload .= "\x08\x01"; // platform (iOS)
        $clientPayload .= "\x12\x06"; // app version
        $clientPayload .= "\x08" . pack('C', $version[0]); // primary   (2)
        $clientPayload .= "\x10" . pack('C', $version[1]); // secondary (16)
        $clientPayload .= "\x18" . pack('C', $version[2]); // tertiary  (4)
        $clientPayload .= "\x1A" . pack('C', strlen($mcc = '250')) . $mcc; // mcc 250
        $clientPayload .= "\x22" . pack('C', strlen($mnc = '099')) . $mnc; // mnc 099

        $osVersionTrimmed = '9.1';

        $clientPayload .= "\x2A" . pack('C', strlen($osVersionTrimmed)) . $osVersionTrimmed; // os version 9.3.2
        $clientPayload .= "\x32\x05\x41\x70\x70\x6C\x65"; // manufacturer Apple


        $deviceNameTrimmed = str_replace('_', ' ', 'iPhone_6s');

        $clientPayload .= "\x3A" . pack('C', strlen($deviceNameTrimmed)) . $deviceNameTrimmed; // Device iPhone 6s


        $uuid = strtoupper(md5($this->username));
        $uuid = preg_replace('#(.{8})(.{4})(.{4})(.{4})(.{12})#', "\\1-\\2-\\3-\\4-\\5",  $uuid);
        if(!empty($this->uuid)){
            $uuid = $this->uuid;
        }
        $clientPayload .= "\x4a" . pack('C', strlen($uuid)) . $uuid;

        $clientPayload .= "\x50\x00"; // Release Channel RELEASE
        $clientPayload .= "\x5A" . pack('C', strlen($lang = 'en')) . $lang; // lang en
        $clientPayload .= "\x62" . pack('C', strlen($locale = 'zz')) . $locale; // locale zz
        $clientPayload .= "\x3A" . pack('C', strlen($nickname = 'John Doe')) . $nickname;

        $encryptedClientPayload = $this->handshakeEncrypt($clientPayload);

        $packet = "\x0a\x30" . $encryptedClientCurvePublic . "\x12" . pack('C', strlen($encryptedClientPayload)) . "\x01" . $encryptedClientPayload;
        $packet = "\x22" . pack('C', strlen($packet)) . "\x01" . $packet;
        $packet = $this->writeStream($packet);

        $this->sendPacket($packet);

        $hkdf = hkdf('', 'sha256', $this->chainKey, 64);
        $this->writeKey = substr($hkdf, 0, 32);
        $this->readKey = substr($hkdf, 32, 32);
        $this->readNonce = 0;
        $this->writeNonce = 0;

        $this->isLogged = true;
    }

    /**
     * Register new packet handler function
     * @param callable $callable callback function
     */
    public function onPacket($callable){
        $this->packetHandler[] = $callable;
    }

    /**
     * Display to stdin parsed node
     * @param array $node parsed xmpp-node
     */
    public function showNode($node){
        if(!is_array($node)){
            try{
                $parsed = $this->parseNode($node);
                $this->showNode($parsed);
            }
            catch(Exception $e){
            }
            return;
        }
        array_walk_recursive($node, function(&$item, &$key){
            $nonPrintable = '#[^\x20-\x7E]#';
            if(is_string($key) && preg_match($nonPrintable, $key)){
                $key = '{BIN:' . bin2hex($key) . '}';
            }
            if(is_string($item) && preg_match($nonPrintable, $item)){
                $item = '{BIN:' . bin2hex($item) . '}';
            }
        });
        /** @noinspection ForgottenDebugOutputInspection */
        var_dump($node);
    }

    /**
     * Recursively parse binary node to associative array
     * @param string $node binary node
     * @param int $size
     * @param int $i
     * @return array
     * @throws Exception
     */
    public function parseNode($node, $size = -1, &$i = 0){
        $attributes = array();
        $prevNode = null;
        while($i < strlen($node) && $size-- !== 0){
            $nodeType = unpack('C', $node[$i++])[1];
            switch($nodeType){
                case 0xF8:
                    $nodeSize = unpack('C', $node[$i++])[1];
                    $nodeValue = $this->parseNode($node, $nodeSize, $i);
                    break;
                case 0xF9:
                    $nodeSize = unpack('n', substr($node, $i, 2))[1];
                    $i += 2;
                    $nodeValue = $this->parseNode($node, $nodeSize, $i);
                    break;
                case 0xFF:
                    $nodeInfo = unpack('C', $node[$i++])[1];
                    $intReduceFlag = $nodeInfo & 0x80;
                    $intSize = $nodeInfo & 0x7F;
                    $nodeValue = bin2hex(substr($node, $i, $intSize));
                    if($intReduceFlag){
                        $nodeValue = substr($nodeValue, 0, -1);
                    }
                    $nodeValue = str_replace('a', '-', $nodeValue);
                    $i += $intSize;
                    break;
                case 0xFB:
                    $nodeInfo = unpack('C', $node[$i++])[1];
                    $intReduceFlag = $nodeInfo & 0x80;
                    $intSize = $nodeInfo & 0x7F;
                    $nodeValue = bin2hex(substr($node, $i, $intSize));
                    if($intReduceFlag){
                        $nodeValue = substr($nodeValue, 0, -1);
                    }
                    $nodeValue = str_replace('a', '-', $nodeValue);
                    $i += $intSize;
                    break;
                case 0xFC:
                    $nodeSize = unpack('C', $node[$i++])[1];
                    $nodeValue = substr($node, $i, $nodeSize);
                    $i += $nodeSize;
                    break;
                case 0xFD:
                    $nodeSize = unpack('N', "\x00" . substr($node, $i, 3))[1];
                    $i += 3;
                    $nodeValue = substr($node, $i, $nodeSize);
                    $i += $nodeSize;
                    break;
                case 0xFA:
                    $nodeValue = $this->parseNode($node, 2, $i);
                    break;
                case 0xEC:
                    $nodeValue = unpack('C', $node[$i++])[1];
                    try{
                        $nodeValue = TokenStaticMap::getString($nodeValue, $nodeType);
                    }
                    catch(Exception $e){
                        throw $e;
                    }
                    break;
                case 0xED:
                    $nodeValue = unpack('C', $node[$i++])[1];
                    try{
                        $nodeValue = TokenStaticMap::getString($nodeValue, $nodeType);
                    }
                    catch(Exception $e){
                        throw $e;
                    }
                    break;
                default:
                    try{
                        $nodeValue = TokenStaticMap::getString($nodeType);
                    }
                    catch(Exception $e){
                        throw $e;
                    }
                    break;
            }
            if(null !== $prevNode){
                $attributes[$prevNode] = $nodeValue;
                $prevNode = null;
            }
            else{
                if(count($attributes) === 0){
                    $attributes[] = $nodeValue;
                }
                else if(is_array($nodeValue)){
                    $attributes[] = $nodeValue;
                }
                else{
                    $prevNode = $nodeValue;
                }
            }
        }
        if(null !== $prevNode){
            $attributes[] = $prevNode;
        }
        if($size < -1){
            return $attributes[0];
        }
        return $attributes;
    }

    /**
     * Add header to binary packet & encrypt them
     * @param string $packet binary packet
     * @return string encrypted packet
     */
    public function writeStream($packet){
        $nonEncryptedPacket = $packet;

        $header = 0;

        if($this->isLogged){
            $packet = $this->encryptStream($packet);
        }

        $header = ($header << 16) | strlen($packet);
        $packet = pack('Cn', $header >> 16, $header & 0xFFFF) . $packet;
        $nonEncryptedPacket = pack('Cn', $header >> 16, $header & 0xFFFF) . $nonEncryptedPacket;


        logger('MITM -> Server');
        logger(bin2hex($nonEncryptedPacket));

        return $packet;
    }

    /**
     * Send packet to server
     * @param string $packet binary packet
     */
    public function sendPacket($packet){
        fwrite($this->socket, $packet);
    }

    /**
     * Determine server IP addr to connect to
     * @return string IP Addr
     * @throws RuntimeException
     */
    public function getServerAddr(){
        $serverNumber = mt_rand(1, 16);

        $xmppServer = dns_get_record(sprintf('e%s.whatsapp.net', $serverNumber), DNS_A);

        if(count($xmppServer) === 0){
            throw new RuntimeException('Cannot get DNS records, connection failed.');
        }

        $xmppServer = $xmppServer[mt_rand(0, count($xmppServer)-1)];

        return $xmppServer['ip'];
    }
}
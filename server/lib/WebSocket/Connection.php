<?php

/**
 * WebSocket Connection class
 *
 * @author Nico Kaiser <nico@kaiser.me>
 */
class WebSocket_Connection {

    private $server;
    private $socket;
    private $handshaked = false;
    private $handshakeKey = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private $application = null;
    private $encrypted;

    public function __construct($server, $socket) {
        $this->server = $server;
        $this->socket = $socket;

        $this->log('Connected');
    }

    private function handshake($data) {
        $this->log('Performing handshake');

        $lines = preg_split("/\r\n/", $data);
        if (count($lines) && preg_match('/<policy-file-request.*>/', $lines[0])) {
            $this->log('Flash policy file request');
            $this->serveFlashPolicy();
            return false;
        }

        if (!preg_match('/\AGET (\S+) HTTP\/1.1\z/', $lines[0], $matches)) {
            $this->log('Invalid request: ' . $lines[0]);
            socket_close($this->socket);
            return false;
        }

        $path = $matches[1];

        foreach ($lines as $line) {
            $line = chop($line);
            if (preg_match('/\A(\S+): (.*)\z/', $line, $matches)) {
                $headers[$matches[1]] = $matches[2];
            }
        }

        $key3 = '';
        preg_match("#\r\n(.*?)\$#", $data, $match) && $key3 = $match[1];

        $origin = isset($headers['Sec-WebSocket-Origin']) ? $headers['Sec-WebSocket-Origin'] : $headers['Origin'];
        $host = $headers['Host'];

        $this->application = $this->server->getApplication(substr($path, 1)); // e.g. '/echo'
        if (!$this->application) {
            $this->log('Invalid application: ' . $path);
            socket_close($this->socket);
            return false;
        }

        $status = '101 Web Socket Protocol Handshake';
        if (array_key_exists('Sec-WebSocket-Key1', $headers)) {
            $this->encrypted = false;
            // draft-76
            $def_header = array(
                'Sec-WebSocket-Origin' => $origin,
                'Sec-WebSocket-Location' => "ws://{$host}{$path}"
            );
            $digest = $this->securityDigest76($headers['Sec-WebSocket-Key1'], $headers['Sec-WebSocket-Key2'], $key3);
        } else {
            $this->encrypted = true;
            $socketAccept = $this->securityDigestHybi10($headers['Sec-WebSocket-Key']);
            // draft-75
            $def_header = array(
                'WebSocket-Origin' => $origin,
                'WebSocket-Location' => "ws://{$host}{$path}",
                'Sec-WebSocket-Accept' => $socketAccept
            );
            $digest = '';
        }
        $header_str = '';
        foreach ($def_header as $key => $value) {
            $header_str .= $key . ': ' . $value . "\r\n";
        }

        $upgrade = "HTTP/1.1 ${status}\r\n" .
                "Upgrade: WebSocket\r\n" .
                "Connection: Upgrade\r\n" .
                "${header_str}\r\n$digest";

                
        socket_write($this->socket, $upgrade, strlen($upgrade));

        $this->handshaked = true;
        $this->log('Handshake sent');

        $this->application->onConnect($this);

        return true;
    }

    public function onData($data) {
        if ($this->handshaked) {
            $this->handle($data);
        } else {
            $this->handshake($data);
        }
    }

    private function handle($data) {
        $chunks = explode(chr(255), $data);

        foreach ($chunks as $key => $chunk) {
            if (!$this->encrypted) {
                if($key == (count($chunks) - 1)) 
                    return true;
                if (substr($chunk, 0, 1) != chr(0)) {
                    $this->log('Data incorrectly framed. Dropping connection');
                    socket_close($this->socket);
                    return false;
                }
                $chunk = substr($chunk, 1);
            } else {
                $chunk = $this->hybi10Decode($chunk);
            }
            $this->application->onData($chunk, $this);
        }

        return true;
    }

    private function serveFlashPolicy() {
        $policy = '<?xml version="1.0"?>' . "\n";
        $policy .= '<!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">' . "\n";
        $policy .= '<cross-domain-policy>' . "\n";
        $policy .= '<allow-access-from domain="*" to-ports="*"/>' . "\n";
        $policy .= '</cross-domain-policy>' . "\n";
        socket_write($this->socket, $policy, strlen($policy));
        socket_close($this->socket);
    }

    public function send($data) {
        $data = $this->encrypted ? $this->hybi10Encode($data) : chr(0) . $data . chr(255);

        if (!@socket_write($this->socket, $data, strlen($data))) {
            @socket_close($this->socket);
            $this->socket = false;
        }
    }

    public function onDisconnect() {
        $this->log('Disconnected', 'info');

        if ($this->application) {
            $this->application->onDisconnect($this);
        }
        socket_close($this->socket);
    }

    private function securityDigestHybi10($key) {
        return base64_encode(sha1($key . $this->handshakeKey, true));
    }

    private function securityDigest76($key1, $key2, $key3) {
        return md5(
                        pack('N', $this->keyToBytes($key1)) .
                        pack('N', $this->keyToBytes($key2)) .
                        $key3, true);
    }

    /**
     * WebSocket draft 76 handshake by Andrea Giammarchi
     * see http://webreflection.blogspot.com/2010/06/websocket-handshake-76-simplified.html
     */
    private function keyToBytes($key) {
        return preg_match_all('#[0-9]#', $key, $number) && preg_match_all('# #', $key, $space) ?
                implode('', $number[0]) / count($space[0]) :
                '';
    }

    public function log($message, $type = 'info') {
        @socket_getpeername($this->socket, $addr, $port);
        $this->server->log('[client ' . $addr . ':' . $port . '] ' . $message, $type);
    }

    /**
     * @link https://github.com/GulDmitry/php-websocket-server 
     * @author Nico Kaiser <nico@kaiser.me>
     * @author Simon Samtleben <web@lemmingzshadow.net> (Added hybi10 support)
     * @author Dmitru Gulyakevich
     * 
     * See http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-10#section-4.2
     * A single-frame unmasked text message
     * 0x81 0x05 0x48 0x65 0x6c 0x6c 0x6f (contains "Hello")
     * A single-frame masked text message
     * 0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58 (contains "Hello")
     * A fragmented unmasked text message
     * 0x01 0x03 0x48 0x65 0x6c (contains "Hel")
     * 0x80 0x02 0x6c 0x6f (contains "lo")
     * Ping request and response
     * 0x89 0x05 0x48 0x65 0x6c 0x6c 0x6f (contains a body of "Hello", but the contents of the body are arbitrary)
     * 0x8a 0x05 0x48 0x65 0x6c 0x6c 0x6f (contains a body of "Hello", matching the body of the ping)
     * 256 bytes binary message in a single unmasked frame
     * 0x82 0x7E 0x0100 [256 bytes of binary data]
     * 64KiB binary message in a single unmasked frame
     * 0x82 0x7F 0x0000000000010000 [65536 bytes of binary data]
     * 0x81 - chr(129);
     * 0x01 - chr(1);
     * 0x80 - chr(128);
     * 0x89 - chr(137);
     * 0x8a - chr(138);
     * 0x82 - chr(130);
     *
     * @param string $data
     */
    private function hybi10Encode($data) {
        $frame = Array();
        $mask = array(rand(0, 255), rand(0, 255), rand(0, 255), rand(0, 255));
        $encodedData = '';
        $frame[0] = 0x81;
        $dataLength = strlen($data);


        if ($dataLength <= 125) {
            $frame[1] = $dataLength + 128;
        } else {
            $frame[1] = 254;
            $frame[2] = $dataLength >> 8;
            $frame[3] = $dataLength & 0xFF;
        }
        $frame = array_merge($frame, $mask);
        for ($i = 0; $i < strlen($data); $i++) {
            $frame[] = ord($data[$i]) ^ $mask[$i % 4];
        }

        for ($i = 0; $i < sizeof($frame); $i++) {
            $encodedData .= chr($frame[$i]);
        }

        return $encodedData;
    }

    private function hybi10Decode($data) {
        $bytes = $data;
        $dataLength = '';
        $mask = '';
        $coded_data = '';
        $decodedData = '';
        $secondByte = sprintf('%08b', ord($bytes[1]));
        $masked = ($secondByte[0] == '1') ? true : false;
        $dataLength = ($masked === true) ? ord($bytes[1]) & 127 : ord($bytes[1]);

        if ($masked === true) {
            if ($dataLength === 126) {
                $mask = substr($bytes, 4, 4);
                $coded_data = substr($bytes, 8);
            } elseif ($dataLength === 127) {
                $mask = substr($bytes, 10, 4);
                $coded_data = substr($bytes, 14);
            } else {
                $mask = substr($bytes, 2, 4);
                $coded_data = substr($bytes, 6);
            }
            for ($i = 0; $i < strlen($coded_data); $i++) {
                $decodedData .= $coded_data[$i] ^ $mask[$i % 4];
            }
        } else {
            if ($dataLength === 126) {
                $decodedData = substr($bytes, 4);
            } elseif ($dataLength === 127) {
                $decodedData = substr($bytes, 10);
            } else {
                $decodedData = substr($bytes, 2);
            }
        }

        return $decodedData;
    }

}
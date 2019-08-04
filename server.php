<?php
error_reporting(E_ALL);
set_time_limit(0);// no time limit is imposed
date_default_timezone_set('Europe/Amsterdam');

class WebSocket {
    const LOG_PATH = __DIR__ . '/tmp/';
    const LISTEN_SOCKET_NUM = 9;
    private $sockets = [];
    private $master;
    public function __construct($host, $port) {
        try {
            $this->master = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            // after restarting the server we can reuse this port
            socket_set_option($this->master, SOL_SOCKET, SO_REUSEADDR, 1);
            // bind IP and port to the server socket
            socket_bind($this->master, $host, $port);
            // maximum 9 connections
            socket_listen($this->master, self::LISTEN_SOCKET_NUM);
        } catch (\Exception $e) {
            $err_code = socket_last_error();
            $err_msg = socket_strerror($err_code);
            $this->error([
                'error_init_server',
                $err_code,
                $err_msg
            ]);
        }
        $this->sockets[0] = ['resource' => $this->master];
        $pid = getmypid();
        $this->writeLog(["server: {$this->master} started,pid: {$pid}"]);
        while (true) {
            try {
                $this->createServer();
            } catch (Exception $e) {
                $this->error([
                    'error_create_server',
                    $e->getCode(),
                    $e->getMessage()
                ]);
            }
        }
    }

    private function createServer() {
        $write = $except = NULL;
        // get all the socket resources
        $sockets = array_column($this->sockets, 'resource');
        $read_num = socket_select($sockets, $write, $except, NULL);
        if ($read_num === false) {
            $this->error([
                'error_select',
                $err_code = socket_last_error(),
                socket_strerror($err_code)
            ]);
            return;
        }
        // now $sockets are all the sockets we can read
        foreach ($sockets as $socket) {
            // if a server socket, then handle the connection logic 
            if ($socket == $this->master) {
                $client = socket_accept($this->master);
                // after returning the resource of first client, it will continue to wait for the connection
                if ($client === false) {
                    $this->error([
                        'err_accept',
                        $err_code = socket_last_error(),
                        socket_strerror($err_code)
                    ]);
                    continue;
                } else {
                    self::connect($client);
                    continue;
                }
            } else {
                // if other readable sockets, read their data and process the reply logic
                // data read from socket by socket_recv() will be returned in $buffer
                $bytes = @socket_recv($socket, $buffer, 2048, 0);
                // when the client suddenly breaks, the server receives an 8-byte message
                if ($bytes < 9) {
                    $recv_msg = $this->disconnect($socket);
                } else {
                    if (!$this->sockets[(int)$socket]['handshake']) {
                        self::handShake($socket, $buffer);
                        continue;
                    } else {
                        $recv_msg = self::parse($buffer);
                    }
                }
                array_unshift($recv_msg, 'receive_msg');
                self::handleMsg($socket, $recv_msg);
            }
        }
    }

    /**
     * Add the socket to the connected list, but leave the handshake state false
     * @param $socket
     */
    public function connect($socket) {
        socket_getpeername($socket, $ip, $port);
        $socket_info = [
            'resource' => $socket,
            'username' => '',
            'handshake' => false,
            'ip' => $ip,
            'port' => $port,
        ];
        $this->sockets[(int)$socket] = $socket_info;
        $this->writeLog(array_merge(['socket_connect'], $socket_info));
    }

    /**
     * Client closes the connection
     * @param $socket
     * @return array
     */
    private function disconnect($socket) {
        $recv_msg = [
            'type' => 'logout',
            'content' => $this->sockets[(int)$socket]['username'],
        ];
        socket_getpeername($socket, $ip, $port);
        $this->writeLog([
            'socket_disconnect',
            $this->sockets[(int)$socket]['username'],
            $ip,
            $port
        ]);
        unset($this->sockets[(int)$socket]);
        return $recv_msg;
    }

    /**
     * Use sha1 Algorithm to realize handshake
     * @param $socket
     * @param $buffer
     * @return bool
     */
    public function handShake($socket, $buffer) {
        // get the key of client
        $line_with_key = substr($buffer, strpos($buffer, 'Sec-WebSocket-Key:') + 18);
        $key = trim(substr($line_with_key, 0, strpos($line_with_key, "\r\n")));
        // generate an upgrade key and splice the websocket upgrade header
        // use US Secure Hash Algorithm to create upgrade key
        $upgrade_key = base64_encode(sha1($key . "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", true));
        $upgrade_message = "HTTP/1.1 101 Switching Protocols\r\n";
        $upgrade_message .= "Upgrade: websocket\r\n";
        $upgrade_message .= "Sec-WebSocket-Version: 13\r\n";
        $upgrade_message .= "Connection: Upgrade\r\n";
        $upgrade_message .= "Sec-WebSocket-Accept:" . $upgrade_key . "\r\n\r\n";
        // write upgrade message to the socket
        socket_write($socket, $upgrade_message, strlen($upgrade_message));
        $this->sockets[(int)$socket]['handshake'] = true;
        socket_getpeername($socket, $ip, $port);
        $this->writeLog([
            'hand_shake',
            $socket,
            $ip,
            $port
        ]);
        $msg = [
            'type' => 'handshake',
            'content' => 'done',
        ];
        $msg = $this->build(json_encode($msg));
        socket_write($socket, $msg, strlen($msg));
        return true;
    }

    /**
     * Parsing data
     * @param $buffer
     * @return bool|string
     */
    private function parse($buffer) {
        $decoded = '';
        $len = ord($buffer[1]) & 127;
        if ($len === 126) {
            $masks = substr($buffer, 4, 4);
            $data = substr($buffer, 8);
        } else if ($len === 127) {
            $masks = substr($buffer, 10, 4);
            $data = substr($buffer, 14);
        } else {
            $masks = substr($buffer, 2, 4);
            $data = substr($buffer, 6);
        }
        for ($index = 0; $index < strlen($data); $index++) {
            $decoded .= $data[$index] ^ $masks[$index % 4];
        }
        return json_decode($decoded, true);
    }

    /**
     * Change message into websocket frames
     * @param $msg
     * @return string
     */
    private function build($msg) {
        $frame = [];
        $frame[0] = '81';
        $len = strlen($msg);
        if ($len < 126) {
            $frame[1] = $len < 16 ? '0' . dechex($len) : dechex($len);
        } else if ($len < 65025) {
            $s = dechex($len);
            $frame[1] = '7e' . str_repeat('0', 4 - strlen($s)) . $s;
        } else {
            $s = dechex($len);
            $frame[1] = '7f' . str_repeat('0', 16 - strlen($s)) . $s;
        }
        $data = '';
        for ($i = 0; $i < $len; $i++) {
            $data .= dechex(ord($msg{$i}));
        }
        $frame[2] = $data;
        $data = implode('', $frame);
        return pack("H*", $data);
    }

    /**
     * Handle message
     * @param $socket
     * @param $recv_msg
     *          [
     *          'type'=>user/login/...
     *          'content'=>content
     *          ]
     */
    private function handleMsg($socket, $recv_msg) {
        $msg_type = $recv_msg['type'];
        $msg_content = $recv_msg['content'];
        $response = [];

        switch ($msg_type) {
            case 'login':
                $this->sockets[(int)$socket]['username'] = $msg_content;
                $user_list = array_column($this->sockets, 'username');
                $response['type'] = 'login';
                $response['content'] = $msg_content;
                $response['user_list'] = $user_list;
                break;
            case 'logout':
                $user_list = array_column($this->sockets, 'username');
                $response['type'] = 'logout';
                $response['content'] = $msg_content;
                $response['user_list'] = $user_list;
                break;
            case 'user':
                $username = $this->sockets[(int)$socket]['username'];
                $response['type'] = 'user';
                $response['from'] = $username;
                $response['content'] = $msg_content;
                break;
            case 'private':
                $msg_desti = $recv_msg['destination'];
                $username = $this->sockets[(int)$socket]['username'];
                $response['type'] = 'private';
                $response['from'] = $username;
                $response['to'] = $msg_desti;
                $response['content'] = $msg_content;
                $data = $this->build(json_encode($response));
                foreach ($this->sockets as $socket) {
                    echo($socket);
                    if ($socket['username'] == $msg_desti) {
                        socket_write($socket['resource'], $data, strlen($data));
                    }              
                }
                return;
        }
        $data = $this->build(json_encode($response));
        $this->broadcast($data);
    }

    /**
     * Broadcast message
     * @param $data
     */
    private function broadcast($data) {
        foreach ($this->sockets as $socket) {
            if ($socket['resource'] == $this->master) {
                continue;
            }
            socket_write($socket['resource'], $data, strlen($data));
        }
    }

    /**
     * Write log file
     * @param array $info
     */
    private function writeLog(array $info) {
        $time = date('Y-m-d H:i:s');
        array_unshift($info, $time);
        $info = array_map('json_encode', $info);
        file_put_contents(self::LOG_PATH . 'websocket.log', implode(' | ', $info) . "\r\n", FILE_APPEND);
    }

    /**
     * Write error file
     * @param array $info
     */
    private function error(array $info) {
        $time = date('Y-m-d H:i:s');
        array_unshift($info, $time);
        $info = array_map('json_encode', $info);
        file_put_contents(self::LOG_PATH . 'error.log', implode(' | ', $info) . "\r\n", FILE_APPEND);
    }
}
$ws = new WebSocket("127.0.0.1", "8080");
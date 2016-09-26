<?php
class WebSocketClient {
	public $id; # id编号
	public $socket; # socket
	public $handshake; # 是否建立连接

	public $url; # url
	public $router; # 路由
	public $host;
	public $origin;
	public $key;
	public $params; # 注册的自定义参数将会在这里返回
}

class WebSocketRouter {
	public $router; # 路由

	public function __call($_method, $_arguments) {
		if (isset($this->$_method)) {
			call_user_func_array($this->$_method, $_arguments);
		}
	}

	public function onRouterConnect(WebSocketClient $client) {} # 当符合路由的socket建立连接之后触发
	public function onRouterDisConnect(WebSocketClient $client) {} # 当符合路由的socket断开连接后触发
	public function onMessage(WebSocketClient $client, $msg) {}
	public function onSendMessage(WebSocketClient $client, $msg) {}
}

class WebSocket {
	private $master;
	private $clients = array();
	private $sockets = array();
	private $routers = array(); # 注册路由与方法

	protected $address = "localhost";
	protected $port = 8080;

	public function __construct($address, $port) {
		if ($address == 'localhost') {
			$this->address = $address;
		} else if (preg_match('/^[\d\.]*$/is', $address)) {
			$this->address = long2ip(ip2long($address));
		} else {
			$this->address = $port;
		}

		if (is_numeric($port) && intval($port) > 1024 && intval($port) < 65536) {
			$this->port = $port;
		} else {
			die("Not valid port:" . $port);
		}

		# 初始化一个空的socket
		$this->master = $this->create_socket();
		array_push($this->sockets, $this->master);
		$this->log("start websocket server in $address:$port");
	}

	private function create_socket() {
		$master = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) or
		die("socket_create() failed:" . socket_strerror(socket_last_error())); # IPV4协议， 字节流式， TCP协议

		socket_set_option($master, SOL_SOCKET, SO_REUSEADDR, 1) or
		die("socket_set_option() failed:" . socket_strerror(socket_last_error()));

		socket_bind($master, $this->address, $this->port) or
		die("socket_bind() failed" . socket_strerror(socket_last_error()));

		socket_listen($master, 20) or
		die("socket_listen() failed" . socket_strerror(socket_last_error())); # 同时支持20个连接
		return $master;
	}

	private function connect($clientSocket) {
		$client = new WebSocketClient();
		$client->id = uniqid();
		$client->socket = $clientSocket;
		array_push($this->clients, $client);
		array_push($this->sockets, $clientSocket);
	}

	# 解析参数，获取唯一标识还有用户操作类型
	private function getHeaders($req) {
		$r = $h = $o = $key = null;
		if (preg_match("/GET (.*) HTTP/", $req, $match)) {
			$r = $match[1];
		}

		if (preg_match("/Host: (.*)\r\n/", $req, $match)) {
			$h = $match[1];
		}

		if (preg_match("/Origin: (.*)\r\n/", $req, $match)) {
			$o = $match[1];
		}

		if (preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $req, $match)) {
			$key = $match[1];
		}

		return array($r, $h, $o, $key);
	}

	# 数据封装
	protected function wrap($msg = "", $opcode = 0x1) {
		//默认控制帧为0x1（文本数据）
		$firstByte = 0x80 | $opcode;
		$encodedata = null;
		$len = strlen($msg);

		if (0 <= $len && $len <= 125) {
			$encodedata = chr(0x81) . chr($len) . $msg;
		} else if (126 <= $len && $len <= 0xFFFF) {
			$low = $len & 0x00FF;
			$high = ($len & 0xFF00) >> 8;
			$encodedata = chr($firstByte) . chr(0x7E) . chr($high) . chr($low) . $msg;
		}

		return $encodedata;
	}

	# 数据解包
	protected function unwrap($clientSocket, $msg = "") {
		$opcode = ord(substr($msg, 0, 1)) & 0x0F;
		$payloadlen = ord(substr($msg, 1, 1)) & 0x7F;
		$ismask = (ord(substr($msg, 1, 1)) & 0x80) >> 7;
		$maskkey = null;
		$oridata = null;
		$decodedata = null;

		//关闭连接
		if ($ismask != 1 || $opcode == 0x8) {
			$this->disconnect($clientSocket);
			return null;
		}

		//获取掩码密钥和原始数据
		if ($payloadlen <= 125 && $payloadlen >= 0) {
			$maskkey = substr($msg, 2, 4);
			$oridata = substr($msg, 6);
		} else if ($payloadlen == 126) {
			$maskkey = substr($msg, 4, 4);
			$oridata = substr($msg, 8);
		} else if ($payloadlen == 127) {
			$maskkey = substr($msg, 10, 4);
			$oridata = substr($msg, 14);
		}
		$len = strlen($oridata);
		for ($i = 0; $i < $len; $i++) {
			$decodedata .= $oridata[$i] ^ $maskkey[$i % 4];
		}
		return $decodedata;
	}

	# 协议升级与路由过滤
	private function upgrade(WebSocketClient &$client, $buffer) {
		list($resource, $host, $origin, $key) = $this->getHeaders($buffer);

		# 检查路由是否已经被注册，解析参数，否则不允许连接
		$b = $client;
		if (false == $this->router($b, $resource, $host, $origin, $key)) {
			return false;
		}

		//websocket version 13
		$acceptKey = base64_encode(sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
		$upgrade = "HTTP/1.1 101 Switching Protocol\r\n" .
			"Upgrade: websocket\r\n" .
			"Connection: Upgrade\r\n" .
			"Sec-WebSocket-Accept: " . $acceptKey . "\r\n\r\n"; //必须以两个回车结尾
		socket_write($client->socket, $upgrade, strlen($upgrade));
		$client->handshake = true;

		$this->onRouterConnect($client);
		return true;
	}

	# 校验路由
	private static function checkUrlMatch($regx, $rule) {
		$m1 = explode('/', $regx);
		$m2 = explode('/', $rule);
		$var = array();
		foreach ($m2 as $key => $val) {
			if (0 === strpos($val, '[:')) {
				$val = substr($val, 1, -1);
			}

			if (':' == substr($val, 0, 1)) {
				if ($pos = strpos($val, '|')) {
					// 使用函数过滤
					$val = substr($val, 1, $pos - 1);
				}
				if (strpos($val, '\\')) {
					$type = substr($val, -1);
					if ('d' == $type) {
						if (isset($m1[$key]) && !is_numeric($m1[$key])) {
							return false;
						}

					}
					$name = substr($val, 1, -2);
				} elseif ($pos = strpos($val, '^')) {
					$array = explode('-', substr(strstr($val, '^'), 1));
					if (in_array($m1[$key], $array)) {
						return false;
					}
					$name = substr($val, 1, $pos - 1);
				} else {
					$name = substr($val, 1);
				}
				$var[$name] = isset($m1[$key]) ? $m1[$key] : '';
			} elseif (0 !== strcasecmp($val, $m1[$key])) {
				return false;
			}
		}
		// 成功匹配后返回URL中的动态变量数组
		return $var;
	}

	# socket退出
	public function disconnect($clientSocket) {
		$found = null;
		$n = count($this->clients);
		for ($i = 0; $i < $n; ++$i) {
			if ($this->clients[$i]->socket == $clientSocket) {
				$found = $i;
				break;
			}
		}
		$index = array_search($clientSocket, $this->sockets);
		if (!is_null($found)) {
			$disConnectClient = $this->clients[$found];
			array_splice($this->clients, $found, 1);
			array_splice($this->sockets, $index, 1);
			socket_close($clientSocket);
			$this->onDisconnect($disConnectClient);
		}
	}

	#　通过socket获取对应的客户端
	private function getClientBySocket($socket) {
		foreach ($this->clients as $client) {
			if ($client->socket == $socket) {
				return $client;
			}
		}
		return null;
	}

	# 发送数据
	public function sendMessage(WebSocketClient $client, $msg) {
		$msg = $this->wrap($msg);
		@socket_write($client->socket, $msg, strlen($msg));
		$this->onSendMessage($client, $msg);
	}

	# 当发送数据时触发
	protected function onSendMessage(WebSocketClient $client, $msg) {
		$Router = clone $client->router;
		$Router->onSendMessage($client, $msg);
	}

	# 当收到数据时触发
	protected function onMessage(WebSocketClient $client, $msg) {
		$Router = clone $client->router;
		$Router->onMessage($client, $msg);
	}

	# 当有新的客户端连接时触发
	protected function onRouterConnect(WebSocketClient $client) {
		$Router = clone $client->router;
		$Router->onRouterConnect($client);
	}

	# 当有客户端退出时触发
	protected function onDisconnect(WebSocketClient $client) {
		if ($client->handshake) {
			# 当客户端已经建立起连接之后才会触发
			$Router = clone $client->router;
			$Router->onRouterDisConnect($client);
		}
	}

	# 注册路由
	protected function register(WebSocketRouter $Router) {
		$self = $this;
		$Router->sendMessage = function ($client, $msg) use ($self) {
			$self->sendMessage($client, $msg);
		}; # 动态注册一个发送消息的方法供Router 调用
		array_push($this->routers, $Router);
	}

	public function router(WebSocketClient &$client, $resource, $host, $origin, $key) {
		$breakPoint = false;
		# 校验路由是否注册
		foreach ($this->routers as $Router) {
			$ret = $this::checkUrlMatch($resource, $Router->router); # 校验路由
			if (is_bool($ret)) {
				continue;
			} else {
				$breakPoint = true;
				$client->router = $Router;
				$client->params = $ret;
				break;
			}
		}
		if (!$breakPoint) {
			return false;
		}

		$client->url = $resource;
		$client->host = $host;
		$client->origin = $origin;
		$client->key = $key;
		return true;
	}

	public function run() {
		$this->log("Running...");
		while (true) {
			$socketArr = $this->sockets;
			$write = NULL;
			$except = NULL;
			socket_select($socketArr, $write, $except, NULL);
			foreach ($socketArr as $socket) {
				if ($socket == $this->master) {
					# 主SOCKET 负责接受客户端连接，并创建子socket
					$clientSocket = socket_accept($this->master);
					if ($clientSocket === false) {
						continue;
					} else if ($clientSocket > 0) {
						$this->connect($clientSocket); # 创建客户端连接
					} else {
						$this->log("error socket" . socket_strerror($clientSocket));
					}
				} else {
					$bytes = @socket_recv($socket, $buffer, 2048, 0);
					if ($bytes == 0) {
						$this->disconnect($socket);
					} else {
						$client = $this->getClientBySocket($socket);
						if (!$client->handshake) {
							if (false == $this->upgrade($client, $buffer)) {
								# 收到请求头之后检查路由并返回头，建立socket连接，否则删除该socket
								$this->disconnect($client->socket);
							}
						} else {
							$msg = $this->unwrap($client->socket, $buffer); # 对数据进行解包
							if ($msg) {
								$this->onMessage($client, $msg);
							}

						}
					}
				}
			}
			usleep(100);
		}
	}

	public function log($msg) {
		echo "$msg\n";
	}
}

############################## 自定义代码

class SyncWxAudio extends WebSocketRouter {
	public $router = "/sync_wx_audio/:theme_id/:uid";
	public $memcache;

	public function __construct() {
		return true;
	}

	public function log($msg) {
		echo sprintf("[ %d ] %s\n", time(), $msg);
	}

	public function onRouterConnect(WebSocketClient $client) {
		$msg = sprintf("新用户登录, 登录ID：%s, Url: %s, Param: %s", $client->id, $client->url, var_export($client->params, true));
		$this->log($msg);
	}

	public function onMessage(WebSocketClient $client, $msg) {
		$msg = sprintf("收到来自客户端 %s 的消息：%s", $client->id, $msg);
		$this->log($msg);

		$theme_id = $client->params["theme_id"];
		$uid = $client->params["uid"];

		#
		# same codes

		parent::onMessage($client, $msg); // TODO: Change the autogenerated stub
	}

	public function onRouterDisConnect(WebSocketClient $client) {
		$msg = sprintf("客户端 %s 退出", $client->id);
		$this->log($msg);
	}
}

class RuntimeTool extends WebSocket {
	public function __construct($address, $port) {
		# 注册路由与方法
		$sync_wx_audio = new SyncWxAudio();
		$this->register($sync_wx_audio);

		parent::__construct($address, $port);
	}
}

$cgi = new RuntimeTool("127.0.0.1", 64300);
$cgi->run();
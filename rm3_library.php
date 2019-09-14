<?php

class RM3
{
	private $device_ip;
	private $device_port;
	private $device_mac;
    private $device_wait;
    
    private $keysDir;

	private $key = "";
	private $iv = "";
	private $id = "";
	private $count = 0;

	private $socket = null;

	

	public function __construct($ip, $port, $mac, $wait, $keysDir = "./keys")
	{
		$this->key = hex2bin("097628343fe99e23765c1513accf8b02");
		$this->iv = hex2bin("562e17996d093d28ddb3ba695a2e6f58");
		$this->id = hex2bin("00000000");
		$this->count = rand(0, 0xffff);	
		
		$this->socket = socket_create(AF_INET, SOCK_DGRAM, 0);
		socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
		socket_set_option($this->socket, SOL_SOCKET, SO_BROADCAST, 1);
		socket_bind($this->socket, "0.0.0.0", 0);
		$this->device_ip = $ip;
		$this->device_port = $port;
		$this->device_mac = $mac;
        $this->device_wait = $wait;
        $this->keysDir = $keysDir;

		socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, array('sec' => 5, 'usec' => 0));
		socket_set_option($this->socket, SOL_SOCKET, SO_SNDTIMEO, array('sec' => 5, 'usec' => 0));
	}

	private function sendPacket($rawData)
	{
		//echo "Sending: ".bin2hex($rawData).PHP_EOL;
		socket_sendto($this->socket, $rawData, strlen($rawData), 0, $this->device_ip, $this->device_port);
	}

	public function recvPacket()
	{
		$recvSize = socket_recv($this->socket, $result, 2048, 0);	
		return $result;
	}

	private function encrypt($data)
	{
		$cipher = "AES-128-CBC";
		return openssl_encrypt($data, $cipher, $this->key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $this->iv);
	}

	private function decrypt($data)
	{
		$cipher = "AES-128-CBC";
		return openssl_decrypt($data, $cipher, $this->key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $this->iv);
	}

	public function createPacket($command, $data)
	{
		$this->count = ($this->count + 1) & 0xffff;

		$macParts = explode(":", $this->device_mac);
		$packet = str_pad("", 0x38, chr(0));
		$packet[0x00] = chr(0x5a);
    	$packet[0x01] = chr(0xa5);
    	$packet[0x02] = chr(0xaa);
    	$packet[0x03] = chr(0x55);
    	$packet[0x04] = chr(0x5a);
    	$packet[0x05] = chr(0xa5);
    	$packet[0x06] = chr(0xaa);
    	$packet[0x07] = chr(0x55);
    	$packet[0x24] = chr(0x2a);
    	$packet[0x25] = chr(0x27);
		$packet[0x26] = chr($command);
		$packet[0x28] = chr($this->count & 0xff);
		$packet[0x29] = chr($this->count >> 8);
		$packet[0x2a] = chr(hexdec($macParts[0]));
		$packet[0x2b] = chr(hexdec($macParts[1]));
		$packet[0x2c] = chr(hexdec($macParts[2]));
		$packet[0x2d] = chr(hexdec($macParts[3]));
		$packet[0x2e] = chr(hexdec($macParts[4]));
		$packet[0x2f] = chr(hexdec($macParts[5]));
		$packet[0x30] = $this->id[0];
		$packet[0x31] = $this->id[1];
		$packet[0x32] = $this->id[2];
		$packet[0x33] = $this->id[3];
		
		//echo "  Source data: ".bin2hex($data).PHP_EOL;
		$len = (intval(strlen($data) / 16) + 1) * 16;
		$data = str_pad($data, $len, chr(0));

		$checksum = 0xbeaf;
		for ($i = 0; $i < $len; $i++)
		{
			$checksum += ord($data[$i]);
      		$checksum = $checksum & 0xffff;
		}

		//echo "  Source data: ".bin2hex($data).PHP_EOL;
		$encData = $this->encrypt($data);
		//echo "  Encoded data: ".bin2hex($encData).PHP_EOL;

		$packet[0x34] = chr($checksum & 0xff);
		$packet[0x35] = chr($checksum >> 8);
		$len = strlen($encData);
		for ($i = 0; $i < $len; $i++)
		{
			$packet .= $encData[$i];
		}

		$len = strlen($packet);
		$checksum = 0xbeaf;
		for ($i = 0; $i < $len; $i++)
		{
			$checksum += ord($packet[$i]);
			$checksum = $checksum & 0xffff;
		}
		$packet[0x20] = chr($checksum & 0xff);
		$packet[0x21] = chr($checksum >> 8);
		
		return $packet;
	}

	public function auth()
	{
		if (!is_dir($this->keysDir))
		{
			mkdir($this->keysDir);
		}

		$keyFile = $this->keysDir."/".str_replace(":", "-", $this->device_mac).".key";
		if (file_exists($keyFile))
		{
			$this->key = file_get_contents($keyFile);
			return true;
		}

		$data = str_pad("", 0x50, chr(0));
		$data[0x04] = chr(0x31);
		$data[0x05] = chr(0x31);
		$data[0x06] = chr(0x31);
		$data[0x07] = chr(0x31);
		$data[0x08] = chr(0x31);
		$data[0x09] = chr(0x31);
		$data[0x0a] = chr(0x31);
		$data[0x0b] = chr(0x31);
		$data[0x0c] = chr(0x31);
		$data[0x0d] = chr(0x31);
		$data[0x0e] = chr(0x31);
		$data[0x0f] = chr(0x31);
		$data[0x10] = chr(0x31);
		$data[0x11] = chr(0x31);
		$data[0x12] = chr(0x31);
		$data[0x1e] = chr(0x01);
		$data[0x2d] = chr(0x01);
		$data[0x30] = 'T';
		$data[0x31] = 'e';
		$data[0x32] = 's';
		$data[0x33] = 't';
		$data[0x34] = ' ';
		$data[0x35] = ' ';
		$data[0x36] = '1';

		$packet = $this->createPacket(0x65, $data);
		$this->sendPacket($packet);

		$response = $this->recvPacket();
		$responseData = $this->decrypt(substr($response, 0x38));

		$key = substr($responseData, 0x04, 0x10);
		if (strlen($key) == 0)
		{
			return false;
		}
		if (strlen($key) % 16 != 0)
		{
			return false;
		}

		
		$this->id = substr($responseData, 0x00, 0x04);
		$this->key = $key;
		file_put_contents($keyFile, $this->key);
		//echo "Received key: ".bin2hex($this->key).PHP_EOL;

		return true;
	}

	public function sendCommand($data)
	{
		$packet = $this->createPacket(0x6a, hex2bin("02000000").$data);
		$this->sendPacket($packet);
		return $this->recvPacket();
	}

	public function learnCommand()
	{
		$packet = $this->createPacket(0x6a, hex2bin("03000000000000000000000000000000"));
		$this->sendPacket($packet);
		$this->recvPacket();

		sleep($this->device_wait);

		$packet = $this->createPacket(0x6a, hex2bin("04000000000000000000000000000000"));
		$this->sendPacket($packet);
		$response = $this->recvPacket();

		$err = ord($response[0x22]) | (ord($response[0x23]) << 8);
		if ($err == 0)
		{
			$data = $this->decrypt(substr($response, 0x38));
      		return substr($data, 0x04);
		}
		return "";
	}
}

?>
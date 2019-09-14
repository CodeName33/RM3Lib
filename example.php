<?php
require_once("rm3_library.php");

$server_ip = '192.168.1.253'; 		//your device ip
$server_port = 80;					//your device port (default: 80)
$server_mac = "c8:f7:42:83:6d:2d"; 	//your device mac adderess
$server_wait = 5;					//time to wait remote commands in secs

$dev = new RM3($server_ip, $server_port, $server_mac, $server_wait);
if ($dev->auth())
{
	//$cmd = hex2bin("2600d2008d9314361237123713121312131113121312123713361436131113121213131113121336133613371212131213121212141113121311131213361337123713361436120006029492133613371237131212121312131212121337123713361312121312121312131212371237143613111312121312121312131212121411123714351436123713361300060294921336143513371212141113121212141113361337133613121212131213121212143613361237131213121212131213121212141112131336123713371237133614000d05000000000000");
	//$dev->sendCommand($cmd);


	echo "Press key on your remote".PHP_EOL;
	$command = $dev->learnCommand();
	if (strlen($command) > 0)
	{
		echo "Command received: ".bin2hex($command).PHP_EOL;
		echo "Waiting 5 sec...".PHP_EOL;
		sleep(5);
		echo "Command was repeat".PHP_EOL;
		$dev->sendCommand($command);
	}
	else
	{
		echo "\tNo command was received".PHP_EOL;
	}
}
else
{
	echo "\tError auth device".PHP_EOL;
}

?>

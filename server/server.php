<?php

error_reporting(E_ALL);

//A class named MyLib_Foo_Bar is located in a file: lib1/MyLib/Foo/Bar.php
require dirname(__FILE__) . '/Autoloader.php';

$auto_loader = new AutoLoader;
$auto_loader->registerDirectory(dirname(__FILE__) . '/lib');

$server = new WebSocket_Server('localhost', 8000);
$server->registerApplication('echo', WebSocket_Application_EchoApplication::getInstance());
$server->registerApplication('time', WebSocket_Application_TimeApplication::getInstance());
$server->run();

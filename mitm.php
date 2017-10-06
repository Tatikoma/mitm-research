<?php
require_once __DIR__ . '/server.class.php';
require_once __DIR__ . '/client.class.php';

$config = [
    'listen' => 'tcp://0.0.0.0:5222',
    'server_addr' => '169.47.42.214',
    'username' => '79981234545',
    'password' => hex2bin('20fc8af31d5dd8705bae446aff24bb96aed83badb1bc5ff5504ab0eaf787b1ff'),
];

$client = new Client($config);
$config['client'] = $client;

$server = new Server($config);
$server->listen($config['listen']);

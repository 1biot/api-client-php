<?php

namespace OnebiotApp;

class Client
{
    const V1_VERSION = 'v1';

    /**
     * @var string
     */
    private $server;

    /**
     * @var int
     */
    private $port;

    /**
     * @var string
     */
    private $version;

    public function __construct(string $server, int $port, string $version = self::V1_VERSION)
    {
        $this->server = rtrim($server, '/');
        $this->port = $port;
        $this->version = $version;
    }

    public function createRequest(string $requestType, string $uri)
    {
        $url = sprintf('%s:%d/%s/%s', $this->server, $this->port, $this->version, $uri);
        return new Request($requestType, $url);
    }
}

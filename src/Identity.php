<?php

namespace OnebiotApp;

class Identity
{

    private $authToken;
    private $refreshToken;

    public function __construct(string $authToken, string $refreshToken)
    {
        $this->authToken = $authToken;
        $this->refreshToken = $refreshToken;
    }

    public function getAuthToken(): string
    {
        return $this->authToken;
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }
}
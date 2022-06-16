<?php

namespace OnebiotApp;

class Request
{

    /**
     * @var string
     */
    private $requestType;

    /**
     * @var string
     */
    private $url;

    /**
     * @var string
     */
    private $token;

    public function __construct(string $requestType, string $url)
    {
        $this->requestType = $requestType;
        $this->url = $url;
    }

    public function authorize(string $token): self {
        $this->token = $token;
        return $this;
    }

    /**
     * @param array|\stdClass|null $payload
     * @return Response
     */
    public function execute($payload = null): Response {
        $ch = curl_init($this->url);

        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 2);

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $this->requestType);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $this->getHeaders());

        if ($this->requestType === 'PUT') {
            curl_setopt($ch, CURLOPT_PUT, 1);
        } elseif ($this->requestType === 'DELETE') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }

        if ($payload !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, \json_encode($payload));
        }

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_HEADER, TRUE);

        return new Response($ch);
    }

    private function getHeaders(): array
    {
        $headers = ['Content-Type: application/json'];
        if ($this->token) {
            $headers[] = sprintf('X-AUTH-TOKEN: Bearer %s', $this->token);
        }

        return $headers;
    }
}
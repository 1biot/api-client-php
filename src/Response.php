<?php
namespace OnebiotApp;

class Response {

    use ErrorCodeTrait;

    /**
     * @var bool|string
     */
    private $payload;

    private $headerSize;
    private $headers;

    /**
     * @var mixed
     */
    private $requestInfo;

    /**
     * Response constructor.
     * @param resource|false|\CurlHandle $curlResource
     */
    public function __construct($curlResource) {
        $response = curl_exec($curlResource);
        $this->headerSize = curl_getinfo($curlResource, CURLINFO_HEADER_SIZE);
        $this->headers = substr($response, 0, $this->headerSize);
        $this->payload = substr($response, $this->headerSize);

        $this->errno = curl_errno($curlResource);
        $this->error = curl_error($curlResource);
        $this->requestInfo = curl_getinfo($curlResource);
        curl_close ($curlResource);
    }

    public function isSuccess(): bool {
        return !$this->isFailed();
    }

    public function isFailed(): bool {
        if ($this->getErrorNo()) {
            return true;
        }

        if ($this->getInfo('http_code') >= 300) {
            return true;
        }

        $payload = $this->getEncodedPayload();
        $hasError = is_array($payload) && (($payload['error'] ?? false));
        return $hasError && $payload['error'] >= 400;
    }

    public function getHeaders() {
        return $this->headers;
    }

    public function getHeadersArray(): array {
        $headers = [];
        foreach (explode("\r\n", $this->headers) as $i => $line)
            if ($i === 0) {
                $headers['Status'] = $line;
            } elseif ($line !== '') {
                list ($key, $value) = explode(': ', $line);
                $headers[$key] = $value;
            }

        return $headers;
    }

    public function getHeader(string $headerName): ?string {
        $headers = $this->getHeadersArray();
        return $headers[$headerName] ?? NULL;
    }

    public function getPayload(): string {
        return $this->payload === false ? '' : $this->payload;
    }

    /**
     * @return mixed|array
     */
    public function getEncodedPayload(bool $asArray = false)
    {
        return \json_decode($this->getPayload(), $asArray);
    }

    public function getInfo(string $parameter): ?string {
        return isset($this->requestInfo[$parameter]) ? (string) $this->requestInfo[$parameter] : null;
    }

}

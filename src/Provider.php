<?php

namespace OnebiotApp;

class Provider
{
    const KID_AUTH_TOKEN = 'auth-token-public.api.onebiot.cz';
    const KID_REFRESH_TOKEN = 'refresh-token-public.api.onebiot.cz';

    private $client;
    private $publicKeyFolder;

    /** @var Identity $identity */
    private $identity;

    /** @var ?\Jose\Component\Core\JWKSet $JWKSet */
    private $JWKSet;

    public function __construct(Client $client, ?string $publicKeyFolder = null)
    {
        $this->client = $client;

        $this->publicKeyFolder = $publicKeyFolder;
        if ($this->publicKeyFolder !== null) {
            $this->publicKeyFolder = rtrim($this->publicKeyFolder, '/');
            $authPublicKeyPath = realpath($publicKeyFolder . DIRECTORY_SEPARATOR . self::KID_AUTH_TOKEN . '.pem');
            $refreshPublicKeyPath = realpath($publicKeyFolder . DIRECTORY_SEPARATOR . self::KID_REFRESH_TOKEN . '.pem');
            if (file_exists($authPublicKeyPath) && file_exists($refreshPublicKeyPath)) {
                $this->loadPublicKeys($authPublicKeyPath, $refreshPublicKeyPath);
            }
        }
    }

    public function getClient(): Client
    {
        return $this->client;
    }

    /**
     * @param Identity $identity
     * @param bool $refreshIdentityIfExpired
     * @return Identity
     * @throws AuthenticationException
     * @throws \Exception
     */
    public function loadIdentity(Identity $identity, bool $refreshIdentityIfExpired = false): Identity
    {
        try {
            $this->resetIdentity();
            $this->verifyAuthToken($identity->getAuthToken());
            $this->verifyRefreshToken($identity->getRefreshToken());
            $this->identity = $identity;
            return $this->getIdentity();
        } catch (\Exception $exception) {
            $this->verifyRefreshToken($identity->getRefreshToken());
            if ($refreshIdentityIfExpired) {
                $this->refreshToken($identity);
                return $this->getIdentity();
            }
        }

        return $this->getIdentity();
    }

    public function loadPublicKeys(string $authPublicKeyPath, string $refreshPublicKeyPath)
    {
        $authJWK = self::pemToJWK($authPublicKeyPath, self::KID_AUTH_TOKEN);
        $refreshJWK = self::pemToJWK($refreshPublicKeyPath, self::KID_REFRESH_TOKEN);
        $this->JWKSet = new \Jose\Component\Core\JWKSet([$authJWK, $refreshJWK]);
    }

    /**
     * @return \Jose\Component\Core\JWKSet
     * @throws \InvalidArgumentException
     * @throws \Exception
     */
    public function getJWKSet(): \Jose\Component\Core\JWKSet
    {
        if ($this->JWKSet !== null) {
            return $this->JWKSet;
        }

        $jwkResponse = $this->client->createRequest('GET', '.well-known/jwks.json')
            ->execute();

        if ($jwkResponse->isFailed()) {
            throw new \Exception('Could not obtain JsonWebKeys');
        }

        $this->JWKSet = \Jose\Component\Core\JWKSet::createFromJson($jwkResponse->getPayload());
        if ($this->publicKeyFolder !== null) {
            foreach ($this->JWKSet->all() as $kid => $key) {
                $rsaKey = \Jose\Component\Core\Util\RSAKey::createFromJWK($key);
                file_put_contents($this->publicKeyFolder . DIRECTORY_SEPARATOR . $kid . '.pem', $rsaKey->toPEM());
            }
        }
        return $this->JWKSet;
    }

    /**
     * @param string $token
     * @return \Jose\Easy\JWT
     * @throws \Exception
     */
    public function verifyAuthToken(string $token): \Jose\Easy\JWT
    {
        return $this->verifyToken($token, self::KID_AUTH_TOKEN);
    }

    /**
     * @param string $token
     * @return \Jose\Easy\JWT
     * @throws \Exception
     */
    public function verifyRefreshToken(string $token): \Jose\Easy\JWT
    {
        return $this->verifyToken($token, self::KID_REFRESH_TOKEN);
    }

    /**
     * @param string $user
     * @param string $password
     * @return Identity
     * @throws AuthenticationException
     */
    public function login(string $user, string $password): Identity
    {
        $this->resetIdentity();
        $payload = new \stdClass();
        $payload->user = $user;
        $payload->password = $password;
        $response = $this->client->createRequest('POST', 'user/login')
            ->execute($payload);

        if (!$response->isSuccess()) {
            throw new AuthenticationException('Authentication failed');
        }

        $responseArray = $response->getEncodedPayload(true);
        if (!is_array($responseArray) || !isset($responseArray['data']) || !is_array($responseArray['data'])) {
            throw new AuthenticationException('Authentication failed'); // failure
        }

        $this->loadIdentity(
            new Identity(
                $responseArray['data']['authToken'] ?? '',
                $responseArray['data']['refreshToken'] ?? ''
            )
        );
        return $this->getIdentity();
    }

    /**
     * @param array $data
     * @throws \Exception
     */
    public function registerUser(array $data): void
    {
        $payload = new \stdClass();
        $payload->fullName = $data['fullName'] ?? null;
        $payload->email = $data['email'] ?? null;
        $payload->password = $data['password'] ?? null;
        $payload->passwordConfirm = $data['password'] ?? null;

        $response = $this->client->createRequest('POST', 'user/register')
            ->execute($payload);

        if (!$response->isSuccess()) {
            $responsePayload = $response->getEncodedPayload(true);
            throw new \Exception(
                sprintf('Registration failed. %s', $responsePayload['data'][0]['message'] ?? 'Unknown error')
            );
        }
    }

    public function resetIdentity(): self
    {
        $this->identity = null;
        return $this;
    }

    public function getIdentity(): ?Identity
    {
        return $this->identity;
    }

    /**
     * @param Identity|null $identity
     * @throws AuthenticationException
     */
    private function refreshToken(?Identity $identity = null)
    {
        $identity = $identity ?? $this->getIdentity();
        if (!$identity) {
            throw new AuthenticationException('Could not refresh a token');
        }

        $payload = new \stdClass;
        $payload->refreshToken = $identity->getRefreshToken();

        $refreshTokenResponse = $this->client->createRequest('POST', 'user/refresh-token')
            ->execute($payload);

        if ($refreshTokenResponse->isFailed()) {
            $this->resetIdentity();
            $refreshTokenResponse->getError();
            throw new AuthenticationException('Could not refresh a token');
        }

        $this->loadIdentity(new Identity(
            $refreshTokenResponse->getEncodedPayload()->data->authToken,
            $identity->getRefreshToken()
        ));
    }

    /**
     * @param string $token
     * @param string $key
     * @return \Jose\Easy\JWT
     * @throws \Exception
     */
    protected function verifyToken(string $token, string $key): \Jose\Easy\JWT
    {
        return \Jose\Easy\Load::jws($token)
            ->algs(['RS256'])
            ->iat(500)
            ->exp()
            ->key($this->getJWKSet()->get($key))
            ->run();
    }

    /**
     * @param string $token
     * @param string $key
     * @return \Jose\Component\Signature\JWS|void
     * @throws \Exception
     */
    /*protected function verifyTokenNew(string $token, string $key)
    {
        $manager = new AlgorithmManager([
            new PS256(),
        ]);
        $jwsVerifier = new JWSVerifier($manager);

        $serializerManager = new JWSSerializerManager([new CompactSerializer(),]);
        $jws = $serializerManager->unserialize($token);
        return $jwsVerifier->verifyWithKey(
            $jws,
            $this->getJWKSet()->get($key),
            0
        );
    }*/

    /**
     * @param string $pemFile
     * @return \Jose\Component\Core\JWK|null
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    private static function pemToJWK(string $pemFile, string $kid): ?\Jose\Component\Core\JWK
    {
        if (file_exists($pemFile)) {
            return \Jose\Component\KeyManagement\JWKFactory::createFromKeyFile($pemFile, null, ['kid' => $kid]);
        }

        return null;
    }

}
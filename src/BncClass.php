<?php

namespace TepuiLabs\Bnc;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class BncClass
{
    private const METHOD = 'aes-256-cbc';

    private const SALT = 'Ivan Medvedev';

    public function __construct(
        private readonly string $guid,
        private readonly string $apiUrl
    ) {
    }

    /**
     *  Mediante este método se puede solicitar al API que asigne una nueva llave de
     *  trabajo para encriptar las Operaciones solicitadas.
     *
     * @throws GuzzleException
     */
    public function login(string $masterKey): string
    {
        $client = json_encode([
            'ClientGUID' => $this->guid,
        ]);

        $value = $this->encrypt($client, $masterKey);
        $validation = $this->createHash($client);

        $request = [
            'ClientGUID' => $this->guid,
            'value' => $value,
            'Validation' => $validation,
            'Reference' => '',
            'swTestOperation' => false,
        ];

        $response = $this->makeRequest($request, '/Auth/LogOn');
        $decodedResponse = json_decode($response, true);

        return $this->proSession($decodedResponse['value'], $masterKey);
    }

    /**
     * @throws GuzzleException
     */
    public function requestBanks(string $workKey): bool|array|string|null
    {

        $value = $this->encrypt('{}', $workKey);
        $validation = $this->createHash('{}');

        $request = [
            'ClientGUID' => $this->guid,
            'value' => $value,
            'Validation' => $validation,
            'Reference' => '',
            'swTestOperation' => false,
        ];

        $response = $this->makeRequest($request, '/Services/Banks');
        $decodedResponse = json_decode($response, true);

        return $this->decrypt($decodedResponse['value'], $workKey);
    }

    /**
     * @throws GuzzleException
     */
    public function sendP2P(array $params, string $workKey, string $reference): mixed
    {

        $c2pRequest = json_encode($params);

        $value = $this->encrypt($c2pRequest, $workKey);

        $validation = $this->createHash($c2pRequest);

        $request = [
            'ClientGUID' => $this->guid,
            'value' => $value,
            'Validation' => $validation,
            'Reference' => $reference,
            'swTestOperation' => false,
        ];

        $response = $this->makeRequest($request, '/MobPayment/SendC2P');

        $decodedResponse = json_decode($response, true);

        $decryptedResponse = $this->decrypt($decodedResponse['value'], $workKey);

        return json_decode($decryptedResponse, true);
    }

    /**
     * @throws GuzzleException
     */
    private function makeRequest(array $data, string $url): string
    {
        $client = new Client();

        $fullUrl = $this->apiUrl.$url;

        $response = $client->post($fullUrl, [
            'headers' => [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'Cache-Control' => 'no-cache',
            ],
            'body' => json_encode($data),
        ]);

        return $response->getBody()->getContents();
    }

    private function getHash_pbkdf2(string $masterKey): string
    {
        return hash_pbkdf2('SHA1', $masterKey, self::SALT, 1000, 48, true);
    }

    private function createHash(string $data): string
    {
        return hash('sha256', mb_convert_encoding($data, 'UTF-8'));
    }

    private function proSession(string $data, string $masterKey): string
    {
        $wk = $this->decrypt($data, $masterKey);
        $wk = json_decode($wk, true);

        return $wk['WorkingKey'];
    }

    private function encrypt(string $data, string $masterKey): string
    {
        [$key, $iv] = $this->extracted($masterKey);

        $string = mb_convert_encoding($data, 'UTF-16LE', 'UTF-8');

        return base64_encode(openssl_encrypt($string, self::METHOD, $key, OPENSSL_RAW_DATA, $iv));
    }

    private function decrypt(string $data, string $masterKey): array|bool|string|null
    {
        [$key, $iv] = $this->extracted($masterKey);

        $string = openssl_decrypt(base64_decode($data), self::METHOD, $key, OPENSSL_RAW_DATA, $iv);

        return mb_convert_encoding($string, 'UTF-8', 'UTF-16LE');
    }

    public function extracted(string $masterKey): array
    {
        $pbkdf2 = $this->getHash_pbkdf2($masterKey);
        $key = substr($pbkdf2, 0, 32);
        $iv = substr($pbkdf2, 32, strlen($pbkdf2));

        return [$key, $iv];
    }
}

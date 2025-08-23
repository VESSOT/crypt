<?php

declare(strict_types=1);

namespace Sot\Service\Operations;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class ShowService
{
    protected Client $httpClient;
    protected string $apiUrl;

    public function __construct(
        string $apiUrl,
        Client $httpClient
    ) {
        $this->apiUrl = $apiUrl;
        $this->httpClient = $httpClient;
    }

    public function execute(
        string $key,
        ?string $attribute,
        string $encryptionKey,
        callable $decryptCallback
    ): array {
        $token = getenv('SOT_INT_TOKEN');
        if ($token === false || empty($token)) {
            return [
                'code' => 0,
                'success' => false,
                'error' => 'SOT_INT_TOKEN environment variable not set',
                'value' => ''
            ];
        }

        try {
            $url = $this->apiUrl . '/show/' . urlencode($key);
            if ($attribute !== null) {
                $url .= '?attribute=' . urlencode($attribute);
            }
            
            $response = $this->httpClient->get($url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $token,
                    'Accept' => 'application/json'
                ],
                'http_errors' => false
            ]);

            $statusCode = $response->getStatusCode();
            
            if ($statusCode === 200) {
                $responseData = json_decode($response->getBody()->getContents(), true);
                $encryptedValue = $responseData['value'] ?? '';
                
                if (!empty($encryptedValue)) {
                    try {
                        $decryptedValue = $decryptCallback($encryptedValue);
                        return [
                            'code' => $statusCode,
                            'success' => true,
                            'error' => '',
                            'value' => $decryptedValue
                        ];
                    } catch (\Exception $e) {
                        return [
                            'code' => $statusCode,
                            'success' => false,
                            'error' => 'Decryption failed: ' . $e->getMessage(),
                            'value' => ''
                        ];
                    }
                }
                
                return [
                    'code' => $statusCode,
                    'success' => true,
                    'error' => '',
                    'value' => ''
                ];
            } else {
                $errorData = json_decode($response->getBody()->getContents(), true);
                return [
                    'code' => $statusCode,
                    'success' => false,
                    'error' => $errorData['error'] ?? 'API request failed',
                    'value' => ''
                ];
            }
        } catch (GuzzleException $e) {
            return [
                'code' => $e->getCode(),
                'success' => false,
                'error' => $e->getMessage(),
                'value' => ''
            ];
        }
    }
}

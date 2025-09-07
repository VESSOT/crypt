<?php

declare(strict_types=1);

namespace Sot\Service\Operations;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class DestroyService
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
        $attributes = null
    ): array {
        $token = getenv('VESSOT_INT_TOKEN');
        if ($token === false || empty($token)) {
            return [
                'code' => 0,
                'success' => false,
                'error' => 'VESSOT_INT_TOKEN environment variable not set',
                'value' => ''
            ];
        }

        try {
            $requestData = ['key' => $key];
            if ($attributes !== null) {
                $requestData['attributes'] = $attributes;
            }
            
            $response = $this->httpClient->delete($this->apiUrl . '/destroy', [
                'json' => $requestData,
                'headers' => [
                    'Authorization' => 'Bearer ' . $token,
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json'
                ],
                'http_errors' => false
            ]);

            $statusCode = $response->getStatusCode();
            
            if ($statusCode === 200) {
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

<?php

declare(strict_types=1);

namespace Sot\Service;

use GuzzleHttp\Client;
use Sot\Service\Operations\ShowService;
use Sot\Service\Operations\StoreService;
use Sot\Service\Operations\UpdateService;
use Sot\Service\Operations\DestroyService;

class Data
{
    protected const CIPHER = 'aes-256-gcm';
    protected const TAG_LENGTH = 16;
    
    protected Client $httpClient;
    protected string $apiUrl;
    protected ?string $encryptionKey = null;
    protected ShowService $showService;
    protected StoreService $storeService;
    protected UpdateService $updateService;
    protected DestroyService $destroyService;

    public function __construct(
        string $apiUrl = 'https://sourceoftruth.tech/api'
    ) {
        $this->httpClient = new Client();
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->showService = new ShowService(
            $this->apiUrl,
            $this->httpClient
        );
        $this->storeService = new StoreService(
            $this->apiUrl,
            $this->httpClient
        );
        $this->updateService = new UpdateService(
            $this->apiUrl,
            $this->httpClient
        );
        $this->destroyService = new DestroyService(
            $this->apiUrl,
            $this->httpClient
        );
    }

    public function cryptKeyGenerate(): string
    {
        $existingKey = getenv('SOT_CRYPT_KEY');
        if (
            $existingKey !== false
            && !empty($existingKey)
        ) {
            return '';
        }

        return base64_encode(random_bytes(32));
    }

    protected function loadEncryptionKey(): array
    {
        $existingKey = getenv('SOT_CRYPT_KEY');
        if (
            $existingKey === false
            || empty($existingKey)
        ) {
            return [
                'success' => false,
                'error' => 'SOT_CRYPT_KEY environment variable not set'
            ];
        }
        
        $decodedKey = base64_decode($existingKey, true);
        if (
            $decodedKey === false
            || mb_strlen($decodedKey, '8bit') !== 32
        ) {
            return [
                'success' => false,
                'error' => 'SOT_CRYPT_KEY must be a valid base64-encoded 32-byte key'
            ];
        }
        
        $this->encryptionKey = $decodedKey;
        
        return ['success' => true, 'error' => ''];
    }

    public function show(
        string $key
    ): array {
        $keyResult = $this->loadEncryptionKey();
        if (!$keyResult['success']) {
            return [
                'code' => 0,
                'success' => false,
                'error' => $keyResult['error'],
                'value' => ''
            ];
        }

        return $this->showService->execute(
            $key,
            $this->encryptionKey,
            fn($data) => $this->decrypt($data)
        );
    }

    public function store(
        string $key,
        string $value
    ): array {
        $keyResult = $this->loadEncryptionKey();
        if (!$keyResult['success']) {
            return [
                'code' => 0,
                'success' => false,
                'error' => $keyResult['error'],
                'value' => ''
            ];
        }

        return $this->storeService->execute(
            $key,
            $value,
            fn($data) => $this->encrypt($data)
        );
    }

    public function update(
        string $key,
        string $value
    ): array {
        $keyResult = $this->loadEncryptionKey();
        if (!$keyResult['success']) {
            return [
                'code' => 0,
                'success' => false,
                'error' => $keyResult['error'],
                'value' => ''
            ];
        }

        return $this->updateService->execute(
            $key,
            $value,
            fn($data) => $this->encrypt($data)
        );
    }

    public function destroy(
        string $key
    ): array {
        return $this->destroyService->execute($key);
    }

    protected function encrypt(
        string $plaintext
    ): string {
        if ($this->encryptionKey === null) {
            throw new \RuntimeException('Encryption key not set');
        }

        $ivLength = openssl_cipher_iv_length(self::CIPHER);
        if ($ivLength === false) {
            throw new \RuntimeException('Failed to get IV length for cipher');
        }

        $iv = random_bytes($ivLength);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed');
        }

        $encryptedPayload = $iv . $tag . $ciphertext;
        
        return base64_encode($encryptedPayload);
    }

    protected function decrypt(
        string $base64EncodedPayload
    ): string {
        if ($this->encryptionKey === null) {
            throw new \RuntimeException('Encryption key not set');
        }

        $encryptedPayload = base64_decode($base64EncodedPayload, true);
        if ($encryptedPayload === false) {
            throw new \InvalidArgumentException('Invalid base64 encoded payload');
        }

        $ivLength = openssl_cipher_iv_length(self::CIPHER);
        if ($ivLength === false) {
            throw new \RuntimeException('Failed to get IV length for cipher');
        }

        if (strlen($encryptedPayload) < $ivLength + self::TAG_LENGTH) {
            throw new \InvalidArgumentException('Encrypted payload is too short');
        }

        $iv = substr($encryptedPayload, 0, $ivLength);
        $tag = substr($encryptedPayload, $ivLength, self::TAG_LENGTH);
        $ciphertext = substr($encryptedPayload, $ivLength + self::TAG_LENGTH);

        $decryptedPlaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($decryptedPlaintext === false) {
            throw new \RuntimeException('Decryption failed or data was tampered with');
        }

        return $decryptedPlaintext;
    }
}

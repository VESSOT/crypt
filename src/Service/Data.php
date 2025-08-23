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
        string $key,
        ?string $attribute = null
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
            $attribute,
            $this->encryptionKey,
            fn($data) => $this->smartDecrypt($data)
        );
    }

    public function store(
        string $key,
        $value
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

        // Recursively encrypt individual values while preserving structure
        $encryptedValue = $this->encryptRecursively($value);

        return $this->storeService->execute(
            $key,
            $encryptedValue,
            fn($data) => $data // Data is already encrypted
        );
    }

    public function update(
        string $key,
        $value = null,
        ?array $attributes = null
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

        // Determine what to update
        if ($attributes !== null) {
            // Partial attribute update - merge attributes into existing structure
            $valueToUpdate = $attributes;
        } else {
            // Full value update
            $valueToUpdate = $value;
        }

        // Always use recursive encryption like store() does
        $encryptedValue = $this->encryptRecursively($valueToUpdate);

        return $this->updateService->execute(
            $key,
            $encryptedValue,
            $attributes !== null, // Pass flag to indicate if this is partial update
            fn($data) => $data // Data is already encrypted
        );
    }

    public function destroy(
        string $key,
        $attributes = null
    ): array {
        return $this->destroyService->execute($key, $attributes);
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

    protected function encryptRecursively($data)
    {
        if (is_array($data)) {
            $encrypted = [];
            foreach ($data as $key => $value) {
                $encrypted[$key] = $this->encryptRecursively($value);
            }
            return $encrypted;
        } elseif (is_object($data)) {
            $encrypted = new \stdClass();
            foreach ($data as $key => $value) {
                $encrypted->$key = $this->encryptRecursively($value);
            }
            return $encrypted;
        } else {
            // Encrypt scalar values (string, int, bool, etc.)
            $valueToEncrypt = is_string($data) ? $data : json_encode($data);
            return $this->encrypt($valueToEncrypt);
        }
    }

    protected function smartDecrypt($data)
    {
        // If data is an array or object, we need recursive decryption (nested object/array returned)
        if (is_array($data) || is_object($data)) {
            return $this->decryptRecursively($data);
        } else {
            // Single value returned - decrypt it directly
            try {
                $decryptedValue = $this->decrypt($data);
                // Try to decode as JSON in case it's a JSON-encoded value
                $jsonDecoded = json_decode($decryptedValue, true);
                return ($jsonDecoded !== null && json_last_error() === JSON_ERROR_NONE) ? $jsonDecoded : $decryptedValue;
            } catch (\Exception $e) {
                // If decryption fails, return original value
                return $data;
            }
        }
    }

    protected function decryptRecursively($data)
    {
        if (is_array($data)) {
            $decrypted = [];
            foreach ($data as $key => $value) {
                $decrypted[$key] = $this->decryptRecursively($value);
            }
            return $decrypted;
        } elseif (is_object($data)) {
            $decrypted = new \stdClass();
            foreach ($data as $key => $value) {
                $decrypted->$key = $this->decryptRecursively($value);
            }
            return $decrypted;
        } else {
            // Decrypt scalar values directly - no guessing needed
            try {
                $decryptedValue = $this->decrypt($data);
                // Try to decode as JSON, if it fails return as string
                $jsonDecoded = json_decode($decryptedValue, true);
                return ($jsonDecoded !== null && json_last_error() === JSON_ERROR_NONE) ? $jsonDecoded : $decryptedValue;
            } catch (\Exception $e) {
                // If decryption fails, return original value
                return $data;
            }
        }
    }
}

#include "crypto.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdexcept>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

std::vector<uint8_t> Crypto::hash(const std::string& encryption_key) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<uint8_t> result(32);

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open SHA256 algorithm provider");
    }

    DWORD hashObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjectSize), sizeof(DWORD), &dataSize, 0);

    std::vector<uint8_t> hashObject(hashObjectSize);

    status = BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjectSize, nullptr, 0, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to create hash");
    }

    status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(encryption_key.data())),
                            static_cast<ULONG>(encryption_key.size()), 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to hash data");
    }

    status = BCryptFinishHash(hHash, result.data(), static_cast<ULONG>(result.size()), 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to finish hash");
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return result;
}

std::vector<uint8_t> Crypto::encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open AES algorithm provider");
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                               static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_CBC) * sizeof(wchar_t) + sizeof(wchar_t)), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to set CBC chaining mode");
    }

    DWORD keyObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&keyObjectSize), sizeof(DWORD), &dataSize, 0);

    std::vector<uint8_t> keyObject(keyObjectSize);

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectSize,
                                        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to generate symmetric key");
    }

    std::vector<uint8_t> iv = generate_random_bytes(AES_BLOCK_SIZE);
    std::vector<uint8_t> iv_copy = iv;

    DWORD ciphertextSize = 0;
    status = BCryptEncrypt(hKey, const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
                           nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
                           nullptr, 0, &ciphertextSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to get ciphertext size");
    }

    std::vector<uint8_t> ciphertext(ciphertextSize);
    iv_copy = iv;

    status = BCryptEncrypt(hKey, const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
                           nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
                           ciphertext.data(), ciphertextSize, &ciphertextSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to encrypt data");
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    ciphertext.resize(ciphertextSize);

    std::vector<uint8_t> result;
    result.reserve(iv.size() + ciphertext.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    return result;
}

std::vector<uint8_t> Crypto::decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() < AES_BLOCK_SIZE) {
        throw std::runtime_error("Ciphertext too short");
    }

    std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE);
    std::vector<uint8_t> encrypted_data(ciphertext.begin() + AES_BLOCK_SIZE, ciphertext.end());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open AES algorithm provider");
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                               static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_CBC) * sizeof(wchar_t) + sizeof(wchar_t)), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to set CBC chaining mode");
    }

    DWORD keyObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&keyObjectSize), sizeof(DWORD), &dataSize, 0);

    std::vector<uint8_t> keyObject(keyObjectSize);

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObjectSize,
                                        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to generate symmetric key");
    }

    DWORD plaintextSize = 0;
    std::vector<uint8_t> iv_copy = iv;
    status = BCryptDecrypt(hKey, encrypted_data.data(), static_cast<ULONG>(encrypted_data.size()),
                           nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
                           nullptr, 0, &plaintextSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to get plaintext size");
    }

    std::vector<uint8_t> plaintext(plaintextSize);
    iv_copy = iv;

    status = BCryptDecrypt(hKey, encrypted_data.data(), static_cast<ULONG>(encrypted_data.size()),
                           nullptr, iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
                           plaintext.data(), plaintextSize, &plaintextSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to decrypt data");
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    plaintext.resize(plaintextSize);
    return plaintext;
}

std::vector<uint8_t> Crypto::generate_random_bytes(int count) {
    std::vector<uint8_t> bytes(count);
    NTSTATUS status = BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(count), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return bytes;
}

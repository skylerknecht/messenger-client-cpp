#include "crypto.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdexcept>
#include <cstring>

std::vector<uint8_t> Crypto::hash(const std::string& encryption_key) {
    std::vector<uint8_t> result(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(encryption_key.data()),
           encryption_key.size(), result.data());
    return result;
}

std::vector<uint8_t> Crypto::encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> iv = generate_random_bytes(AES_BLOCK_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);

    // Prepend IV to ciphertext
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

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::vector<uint8_t> plaintext(encrypted_data.size() + AES_BLOCK_SIZE);
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted_data.data(), static_cast<int>(encrypted_data.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return plaintext;
}

std::vector<uint8_t> Crypto::generate_random_bytes(int count) {
    std::vector<uint8_t> bytes(count);
    if (RAND_bytes(bytes.data(), count) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return bytes;
}

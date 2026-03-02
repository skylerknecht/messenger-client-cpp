#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>
#include <vector>
#include <string>

class Crypto {
public:
    static std::vector<uint8_t> hash(const std::string& encryption_key);
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext);
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext);

private:
    static constexpr int AES_BLOCK_SIZE = 16;
    static std::vector<uint8_t> generate_random_bytes(int count);
};

#endif // CRYPTO_H

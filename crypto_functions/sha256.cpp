#include "sha256.h"
#include <mbedtls/sha256.h>

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(32);
    mbedtls_sha256(data.data(), data.size(), hash.data(), 0);
    return hash;
}
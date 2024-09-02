#ifndef MASTER_SHA256_H
#define MASTER_SHA256_H

#include <vector>

/**
 * Computes the SHA-256 Hash of a vector of bytes.
 * @param[in] data the input vector of bytes.
 * @returns the hash (256 bits).
 */
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data);

#endif //MASTER_SHA256_H

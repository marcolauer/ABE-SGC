#include "HashChain.h"
#include "random.h"
#include "crypto_functions/sha256.h"

HashChain *HashChain::create_single(const int byte_length) {
    return new HashChain(std::vector<std::vector<unsigned char>>{byte_vector_random(byte_length)}, 1, 0, byte_length);
}

HashChain *HashChain::create_chain(const int byte_length, const int length) {
    const std::vector<std::vector<unsigned char>> chain(length);
    const auto hash_chain = new HashChain(chain, length, 0, byte_length);
    hash_chain->reconfigure();
    return hash_chain;
}

HashChain *HashChain::from_single_key(const std::vector<unsigned char>& key, const int byte_length) {
    return new HashChain(std::vector<std::vector<unsigned char>>{key}, 1, 0, byte_length);
}

HashChain::HashChain(std::vector<std::vector<unsigned char>> chain, const int length, const int current, const int byte_length) {
    this->chain = std::move(chain);
    this->length = length;
    this->current = current;
    this->byte_length = byte_length;
}

std::vector<unsigned char> HashChain::get_current() const {
    return chain[current];
}

bool HashChain::next() {
    if (current < length - 1) {
        ++current;
        return false;
    }
    reconfigure();
    current = 0;
    return true;
}

void HashChain::reconfigure() {
    chain[length - 1] = byte_vector_random(byte_length);
    for (int i = length - 2; i >= 0; --i) {
        chain[i] = sha256(chain[i + 1]);
        chain[i].resize(byte_length);
    }
}

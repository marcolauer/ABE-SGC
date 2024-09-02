#include "random.h"
#include <fstream>

std::vector<unsigned char> byte_vector_random(const int length) {
    std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary);
    std::vector<char> data(length);
    urandom.read(data.data(), length);
    return {data.begin(), data.end()};
}

unsigned char *bytes_new_random(const int length) {
    std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary);
    auto *data = new char[length];
    urandom.read(data, length);
    return reinterpret_cast<unsigned char *>(data);
}

void bytes_random(unsigned char *data, const int length) {
    std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary);
    urandom.read(reinterpret_cast<char *>(data), length);
}
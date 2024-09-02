#include "serialize.h"

// everything big endian

void serialize_bn_t(std::vector<unsigned char>& data, bn_t x) {
    const uint8_t length = bn_size_bin(x);
    data.reserve(data.size() + length + 4);
    serialize_int<uint8_t>(data, length);
    unsigned char *pos = &data.back() + 1;
    data.insert(data.end(), length, 0);
    bn_write_bin(pos, length, x);
}

void deserialize_bn_t(bn_t x, const std::vector<unsigned char>& data, int *offset_ptr) {
    const auto length = deserialize_int<uint8_t>(data, offset_ptr);
    bn_read_bin(x, data.data() + *offset_ptr, length);
    *offset_ptr += length;
}

void serialize_g1_t(std::vector<unsigned char>& data, g1_t x) {
    constexpr bool compression = true;
    const uint8_t length = g1_size_bin(x, compression);
    data.reserve(data.size() + length + 1);
    serialize_int<uint8_t>(data, length);
    unsigned char *pos = &data.back() + 1;
    data.insert(data.end(), length, 0);
    g1_write_bin(pos, length, x, compression);
}

void deserialize_g1_t(g1_t x, const std::vector<unsigned char>& data, int *offset_ptr) {
    const auto length = deserialize_int<uint8_t>(data, offset_ptr);
    g1_read_bin(x, data.data() + *offset_ptr, length);
    *offset_ptr += length;
}

void serialize_g2_t(std::vector<unsigned char>& data, g2_t x) {
    constexpr bool compression = true;
    const uint8_t length = g2_size_bin(x, compression);
    data.reserve(data.size() + length + 1);
    serialize_int<uint8_t>(data, length);
    unsigned char *pos = &data.back() + 1;
    data.insert(data.end(), length, 0);
    g2_write_bin(pos, length, x, compression);
}

void deserialize_g2_t(g2_t x, const std::vector<unsigned char>& data, int *offset_ptr) {
    const auto length = deserialize_int<uint8_t>(data, offset_ptr);
    g2_read_bin(x, data.data() + *offset_ptr, length);
    *offset_ptr += length;
}

void serialize_gt_t(std::vector<unsigned char>& data, gt_t x) {
    constexpr bool compression = true;
    const uint16_t length = gt_size_bin(x, compression);
    data.reserve(data.size() + length + 4);
    serialize_int<uint16_t>(data, length);
    unsigned char *pos = &data.back() + 1;
    data.insert(data.end(), length, 0);
    gt_write_bin(pos, length, x, compression);
}

void deserialize_gt_t(gt_t x, const std::vector<unsigned char>& data, int *offset_ptr) {
    const auto length = deserialize_int<uint16_t>(data, offset_ptr);
    gt_read_bin(x, data.data() + *offset_ptr, length);
    *offset_ptr += length;
}
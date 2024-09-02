#ifndef MASTER_SERIALIZE_H
#define MASTER_SERIALIZE_H

#include <vector>
#include <map>
#include <iostream>
#include "MSPMatrix.h"
#include "TTree.h"
#include "relic_util.h"
#include "util.h"
extern "C" {
#include <relic.h>
}

// This header file contains functions for serializing and deserializing frequently used data types.

/**
 * Serializes an integer value to bytes.
 * @tparam INT_TYPE the type of integer to serialize.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] x the integer to serialize.
 */
template<typename INT_TYPE, std::enable_if_t<std::is_integral_v<INT_TYPE>, bool> = true>
void serialize_int(std::vector<unsigned char>& data, const INT_TYPE x) {
    data.reserve(data.size() + sizeof(INT_TYPE));
    for (int i = sizeof(INT_TYPE) - 1; i >= 0; --i) {
        data.push_back((x & (0xff << (i * 8))) >> (i * 8));
    }
}

/**
 * Deserializes an integer value from bytes.
 * @tparam INT_TYPE the type of integer to deserialize.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the integer in `data`. This value is
 *      incremented by the size of the serialized integer in bytes.
 * @returns the deserialized integer.
 */
template<typename INT_TYPE, std::enable_if_t<std::is_integral_v<INT_TYPE>, bool> = true>
INT_TYPE deserialize_int(const std::vector<unsigned char>& data, int *offset_ptr) {
    INT_TYPE result = 0;
    for (int i = sizeof(INT_TYPE) - 1; i >= 0; --i) {
        result |= (data[(*offset_ptr)++]) << (i * 8);
    }
    return result;
}

/**
 * Serializes a vector of integer values to bytes.
 * @tparam INT_TYPE the type of integer to serialize.
 * @tparam SIZE_TYPE the type of integer used to serialize the vector length.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] vec the vector to serialize.
 */
template<typename INT_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<INT_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_int_vector(std::vector<unsigned char>& data, const std::vector<INT_TYPE>& vec) {
    const size_t length = vec.size();
    if (length > std::numeric_limits<SIZE_TYPE>::max()) {
        std::cerr << "Serialization error: Vector length too large for SIZE_TYPE " << typeid(SIZE_TYPE).name() << std::endl;
        exit(-1);
    }
    data.reserve(data.size() + sizeof(SIZE_TYPE) + sizeof(INT_TYPE) * length);
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto x : vec) {
        serialize_int<INT_TYPE>(data, x);
    }
}

/**
 * Deserializes a vector of integer values from bytes.
 * @tparam INT_TYPE the type of integer to deserialize.
 * @tparam SIZE_TYPE the type of integer used to deserialize the vector length.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the vector in `data`. This value is
 *      incremented by the size of the serialized vector in bytes.
 * @returns the deserialized vector.
 */
template<typename INT_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<INT_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::vector<INT_TYPE> deserialize_int_vector(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::vector<INT_TYPE> result(length);
    for (SIZE_TYPE i = 0; i < length; ++i) {
        result[i] = deserialize_int<INT_TYPE>(data, offset_ptr);
    }
    return result;
}

/**
 * Serializes a vector of bytes to bytes.
 * @tparam SIZE_TYPE the type of integer used to serialize the vector length.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] vec the vector to serialize.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_bytes_vector(std::vector<unsigned char>& data, const std::vector<std::vector<unsigned char>>& vec) {
    const size_t length = vec.size();
    if (length > std::numeric_limits<SIZE_TYPE>::max()) {
        std::cerr << "Serialization error: Vector length too large for SIZE_TYPE " << typeid(SIZE_TYPE).name() << std::endl;
        exit(-1);
    }
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& bytes : vec) {
        const size_t length2 = bytes.size();
        if (length2 > std::numeric_limits<SIZE_TYPE>::max()) {
            std::cerr << "Serialization error: Vector length too large for SIZE_TYPE " << typeid(SIZE_TYPE).name() << std::endl;
            exit(-1);
        }
        serialize_int<SIZE_TYPE>(data, length2);
        data.insert(data.end(), bytes.begin(), bytes.end());
    }
}

/**
 * Deserializes a vector of bytes from bytes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the vector length.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the vector in `data`. This value is
 *      incremented by the size of the serialized vector in bytes.
 * @returns the deserialized vector.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::vector<std::vector<unsigned char>> deserialize_bytes_vector(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::vector<std::vector<unsigned char>> result(length);
    for (SIZE_TYPE i = 0; i < length; ++i) {
        const SIZE_TYPE length2 = deserialize_int<SIZE_TYPE>(data, offset_ptr);
        result[i] = std::vector<unsigned char>{data.begin() + *offset_ptr, data.begin() + *offset_ptr + length2};
        *offset_ptr += length2;
    }
    return result;
}

/**
 * Serializes a TAttribute to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] tAttribute the TAttribute to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true>
void serialize_tattribute(std::vector<unsigned char>& data, const TAttribute& tAttribute) {
    serialize_int<ATTR_TYPE>(data, tAttribute.get_attribute());
    serialize_int<OCCUR_TYPE>(data, tAttribute.get_occurrence());
}

/**
 * Deserializes a TAttribute from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the TAttribute in `data`. This
 *      value is incremented by the size of the serialized TAttribute in bytes.
 * @returns the deserialized TAttribute.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true>
TAttribute deserialize_tattribute(const std::vector<unsigned char>& data, int *offset_ptr) {
    const int attribute = deserialize_int<ATTR_TYPE>(data, offset_ptr);
    const int occurance = deserialize_int<OCCUR_TYPE>(data, offset_ptr);
    return {attribute, occurance};
}

/**
 * Serializes a MSPAttribute to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] msp_attribute the MSPAttribute to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true>
void serialize_msp_attribute(std::vector<unsigned char>& data, const MSPAttribute& msp_attribute) {
    serialize_int<ATTR_TYPE>(data, msp_attribute.get_attribute());
    serialize_int<OCCUR_TYPE>(data, msp_attribute.get_occurrence());
}

/**
 * Deserializes a MSPAttribute from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the MSPAttribute in `data`. This
 *      value is incremented by the size of the serialized TAttribute in bytes.
 * @returns the deserialized MSPAttribute.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true>
MSPAttribute deserialize_msp_attribute(const std::vector<unsigned char>& data, int *offset_ptr) {
    const int attribute = deserialize_int<ATTR_TYPE>(data, offset_ptr);
    const int occurance = deserialize_int<OCCUR_TYPE>(data, offset_ptr);
    return {attribute, occurance};
}

/**
 * Serializes a TTree policy to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute values.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the attribute occurrence count.
 * @tparam TN_TYPE the type of integer used to serialize the values t and n in the threshold nodes.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] policy the TTree policy to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename TN_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<TN_TYPE>, bool> = true>
void serialize_ttree_policy(std::vector<unsigned char>& data, TTree *policy) {
    // Pattern match
    if (isType<TThreshold>(*policy)) {
        data.push_back('t');
        const auto tThreshold = dynamic_cast<TThreshold *>(policy);
        const TN_TYPE n = tThreshold->get_n();
        serialize_int<TN_TYPE>(data, tThreshold->get_t());
        serialize_int<TN_TYPE>(data, n);
        for (TN_TYPE i = 0; i < n; ++i) {
            serialize_ttree_policy<ATTR_TYPE, OCCUR_TYPE, TN_TYPE>(data, tThreshold->get_child(i));
        }
    } else {
        data.push_back('a');
        serialize_int<ATTR_TYPE>(data, dynamic_cast<TAttribute *>(policy)->get_attribute());
        serialize_int<ATTR_TYPE>(data, dynamic_cast<TAttribute *>(policy)->get_occurrence());
    }
}

/**
 * Deserializes a TTree policy from bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute values.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the attribute occurrence count.
 * @tparam TN_TYPE the type of integer used to serialize the values t and n in the threshold nodes.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the TTree policy in `data`. This
 *      value is incremented by the size of the serialized TTree policy in bytes.
 * @returns the deserialized TTree policy.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename TN_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<TN_TYPE>, bool> = true>
TTree *deserialize_ttree_policy(const std::vector<unsigned char>& data, int *offset_ptr) {
    if (data[(*offset_ptr)++] == 't') {
        const TN_TYPE t = deserialize_int<TN_TYPE>(data, offset_ptr);
        const TN_TYPE n = deserialize_int<TN_TYPE>(data, offset_ptr);
        std::vector<TTree *> children(n);
        for (TN_TYPE i = 0; i < n; ++i) {
            children[i] = deserialize_ttree_policy<ATTR_TYPE, OCCUR_TYPE, TN_TYPE>(data, offset_ptr);
        }
        return new TThreshold(t, n, children);
    }
    const int attribute = deserialize_int<ATTR_TYPE>(data, offset_ptr);
    const int occurance = deserialize_int<OCCUR_TYPE>(data, offset_ptr);
    return new TAttribute(attribute, occurance);
}

/**
 * Serializes a bn_t value to bytes.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] x the bn_t value to serialize.
 */
void serialize_bn_t(std::vector<unsigned char>& data, bn_t x);

/**
 * Deserializes a bn_t value from bytes.
 * @param[out] x the deserialized bn_t value.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the bn_t value in `data`. This value
 *      is incremented by the size of the serialized bn_t value in bytes.
 */
void deserialize_bn_t(bn_t x, const std::vector<unsigned char>& data, int *offset_ptr);

/**
 * Serializes a g1_t value to bytes.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] x the g1_t value to serialize.
 */
void serialize_g1_t(std::vector<unsigned char>& data, g1_t x);

/**
 * Deserializes a g1_t value from bytes.
 * @param[out] x the deserialized g1_t value.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the g1_t value in `data`. This value
 *      is incremented by the size of the serialized g1_t value in bytes.
 */
void deserialize_g1_t(g1_t x, const std::vector<unsigned char>& data, int *offset_ptr);

/**
 * Serializes a g2_t value to bytes.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] x the g2_t value to serialize.
 */
void serialize_g2_t(std::vector<unsigned char>& data, g2_t x);

/**
 * Deserializes a g2_t value from bytes.
 * @param[out] x the deserialized g2_t value.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the g2_t value in `data`. This value
 *      is incremented by the size of the serialized g2_t value in bytes.
 */
void deserialize_g2_t(g2_t x, const std::vector<unsigned char>& data, int *offset_ptr);

/**
 * Serializes a gt_t value to bytes.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] x the gt_t value to serialize.
 */
void serialize_gt_t(std::vector<unsigned char>& data, gt_t x);

/**
 * Deserializes a gt_t value from bytes.
 * @param[out] x the deserialized gt_t value.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the gt_t value in `data`. This value
 *      is incremented by the size of the serialized gt_t value in bytes.
 */
void deserialize_gt_t(gt_t x, const std::vector<unsigned char>& data, int *offset_ptr);

/**
 * Serializes a vector of bn_t values to bytes.
 * @tparam SIZE_TYPE the type of integer used to serialize the vector length.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] vec the vector to serialize.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_bn_t_vector(std::vector<unsigned char>& data, const std::vector<bn_t *>& vec) {
    const SIZE_TYPE length = vec.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (auto val : vec) {
        serialize_bn_t(data, *val);
    }
}

/**
 * Deserializes a vector of bn_t values from bytes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the vector length.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the vector in `data`. This value is
 *      incremented by the size of the serialized vector in bytes.
 * @returns the deserialized vector.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::vector<bn_t *> deserialize_bn_t_vector(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::vector<bn_t *> result(length);
    for (SIZE_TYPE i = 0; i < length; ++i) {
        auto value = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*value);
        deserialize_bn_t(*value, data, offset_ptr);
        result[i] = value;
    }
    return result;
}

/**
 * Serializes a vector of g1_t values to bytes.
 * @tparam SIZE_TYPE the type of integer used to serialize the vector length.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] vec the vector to serialize.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_g1_t_vector(std::vector<unsigned char>& data, const std::vector<g1_t *>& vec) {
    const SIZE_TYPE length = vec.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (auto val : vec) {
        serialize_g1_t(data, *val);
    }
}

/**
 * Deserializes a vector of g1_t values from bytes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the vector length.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the vector in `data`. This value is
 *      incremented by the size of the serialized vector in bytes.
 * @returns the deserialized vector.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::vector<g1_t *> deserialize_g1_t_vector(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::vector<g1_t *> result(length);
    for (SIZE_TYPE i = 0; i < length; ++i) {
        auto value = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*value);
        deserialize_g1_t(*value, data, offset_ptr);
        result[i] = value;
    }
    return result;
}

/**
 * Serializes a vector of g2_t values to bytes.
 * @tparam SIZE_TYPE the type of integer used to serialize the vector length.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] vec the vector to serialize.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_g2_t_vector(std::vector<unsigned char>& data, const std::vector<g2_t *>& vec) {
    const SIZE_TYPE length = vec.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (auto val : vec) {
        serialize_g2_t(data, *val);
    }
}

/**
 * Deserializes a vector of g2_t values from bytes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the vector length.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the vector in `data`. This value is
 *      incremented by the size of the serialized vector in bytes.
 * @returns the deserialized vector.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::vector<g2_t *> deserialize_g2_t_vector(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::vector<g2_t *> result(length);
    for (SIZE_TYPE i = 0; i < length; ++i) {
        auto value = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*value);
        deserialize_g2_t(*value, data, offset_ptr);
        result[i] = value;
    }
    return result;
}

/**
 * Serializes a vector of gt_t values to bytes.
 * @tparam SIZE_TYPE the type of integer used to serialize the vector length.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] vec the vector to serialize.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_gt_t_vector(std::vector<unsigned char>& data, const std::vector<gt_t *>& vec) {
    const SIZE_TYPE length = vec.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (auto val : vec) {
        serialize_gt_t(data, *val);
    }
}

/**
 * Deserializes a vector of gt_t values from bytes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the vector length.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the vector in `data`. This value is
 *      incremented by the size of the serialized vector in bytes.
 * @returns the deserialized vector.
 */
template<typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::vector<gt_t *> deserialize_gt_t_vector(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::vector<gt_t *> result(length);
    for (SIZE_TYPE i = 0; i < length; ++i) {
        auto value = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*value);
        deserialize_gt_t(*value, data, offset_ptr);
        result[i] = value;
    }
    return result;
}

/**
 * Serializes a map of integers to bn_t values to bytes.
 * @tparam KEY_TYPE the type of integer used to serialize the map keys.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename KEY_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_int_bn_t_map(std::vector<unsigned char>& data, const std::map<KEY_TYPE, bn_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_int<KEY_TYPE>(data, k);
        serialize_bn_t(data, *v);
    }
}

/**
 * Deserializes a map of integers to bn_t values from bytes.
 * @tparam KEY_TYPE the type of integer used to deserialize the map keys.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename KEY_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<KEY_TYPE, bn_t *> deserialize_int_bn_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<KEY_TYPE, bn_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        KEY_TYPE key = deserialize_int<KEY_TYPE>(data, offset_ptr);
        auto value = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*value);
        deserialize_bn_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of integers to g1_t values to bytes.
 * @tparam KEY_TYPE the type of integer used to serialize the map keys.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename KEY_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_int_g1_t_map(std::vector<unsigned char>& data, const std::map<KEY_TYPE, g1_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_int<KEY_TYPE>(data, k);
        serialize_g1_t(data, *v);
    }
}

/**
 * Deserializes a map of integers to g1_t values from bytes.
 * @tparam KEY_TYPE the type of integer used to deserialize the map keys.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename KEY_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<KEY_TYPE, g1_t *> deserialize_int_g1_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<KEY_TYPE, g1_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        KEY_TYPE key = deserialize_int<KEY_TYPE>(data, offset_ptr);
        auto value = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*value);
        deserialize_g1_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of integers to g2_t values to bytes.
 * @tparam KEY_TYPE the type of integer used to serialize the map keys.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename KEY_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_int_g2_t_map(std::vector<unsigned char>& data, const std::map<KEY_TYPE, g2_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_int<KEY_TYPE>(data, k);
        serialize_g2_t(data, *v);
    }
}

/**
 * Deserializes a map of integers to g2_t values from bytes.
 * @tparam KEY_TYPE the type of integer used to deserialize the map keys.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename KEY_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<KEY_TYPE, g2_t *> deserialize_int_g2_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<KEY_TYPE, g2_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        KEY_TYPE key = deserialize_int<KEY_TYPE>(data, offset_ptr);
        auto value = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*value);
        deserialize_g2_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of integers to gt_t values to bytes.
 * @tparam KEY_TYPE the type of integer used to serialize the map keys.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename KEY_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_int_gt_t_map(std::vector<unsigned char>& data, const std::map<KEY_TYPE, gt_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_int<KEY_TYPE>(data, k);
        serialize_gt_t(data, *v);
    }
}

/**
 * Deserializes a map of integers to gt_t values from bytes.
 * @tparam KEY_TYPE the type of integer used to deserialize the map keys.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename KEY_TYPE, typename SIZE_TYPE, std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<KEY_TYPE, gt_t *> deserialize_int_gt_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<KEY_TYPE, gt_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        KEY_TYPE key = deserialize_int<KEY_TYPE>(data, offset_ptr);
        auto value = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*value);
        deserialize_gt_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of TAttributes to bn_t values to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value of the TAttributes.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count of the TAttributes.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_tattribute_bn_t_map(std::vector<unsigned char>& data, const std::map<TAttribute, bn_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_tattribute<ATTR_TYPE, OCCUR_TYPE>(data, k);
        serialize_bn_t(data, *v);
    }
}

/**
 * Deserializes a map of TAttributes to bn_t values from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value of the TAttributes.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count of the TAttributes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<TAttribute, bn_t *> deserialize_tattribute_bn_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<TAttribute, bn_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        TAttribute key = deserialize_tattribute<ATTR_TYPE, OCCUR_TYPE>(data, offset_ptr);
        auto value = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*value);
        deserialize_bn_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of TAttributes to g1_t values to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value of the TAttributes.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count of the TAttributes.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_tattribute_g1_t_map(std::vector<unsigned char>& data, const std::map<TAttribute, g1_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_tattribute<ATTR_TYPE, OCCUR_TYPE>(data, k);
        serialize_g1_t(data, *v);
    }
}

/**
 * Deserializes a map of TAttributes to g1_t values from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value of the TAttributes.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count of the TAttributes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<TAttribute, g1_t *> deserialize_tattribute_g1_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<TAttribute, g1_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        TAttribute key = deserialize_tattribute<ATTR_TYPE, OCCUR_TYPE>(data, offset_ptr);
        auto value = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*value);
        deserialize_g1_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of TAttributes to g2_t values to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value of the TAttributes.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count of the TAttributes.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_tattribute_g2_t_map(std::vector<unsigned char>& data, const std::map<TAttribute, g2_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_tattribute<ATTR_TYPE, OCCUR_TYPE>(data, k);
        serialize_g2_t(data, *v);
    }
}

/**
 * Deserializes a map of TAttributes to g2_t values from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value of the TAttributes.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count of the TAttributes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<TAttribute, g2_t *> deserialize_tattribute_g2_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<TAttribute, g2_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        TAttribute key = deserialize_tattribute<ATTR_TYPE, OCCUR_TYPE>(data, offset_ptr);
        auto value = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*value);
        deserialize_g2_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of TAttributes to gt_t values to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value of the TAttributes.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count of the TAttributes.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_tattribute_gt_t_map(std::vector<unsigned char>& data, const std::map<TAttribute, gt_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_tattribute<ATTR_TYPE, OCCUR_TYPE>(data, k);
        serialize_gt_t(data, *v);
    }
}

/**
 * Deserializes a map of TAttributes to gt_t values from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value of the TAttributes.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count of the TAttributes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<TAttribute, gt_t *> deserialize_tattribute_gt_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<TAttribute, gt_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        TAttribute key = deserialize_tattribute<ATTR_TYPE, OCCUR_TYPE>(data, offset_ptr);
        auto value = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*value);
        deserialize_gt_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of MSPAttributes to bn_t values to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value of the MSPAttributes.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count of the MSPAttributes.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_msp_attribute_bn_t_map(std::vector<unsigned char>& data, const std::map<MSPAttribute, bn_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_msp_attribute<ATTR_TYPE, OCCUR_TYPE>(data, k);
        serialize_bn_t(data, *v);
    }
}

/**
 * Deserializes a map of MSPAttributes to bn_t values from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value of the MSPAttributes.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count of the MSPAttributes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<MSPAttribute, bn_t *> deserialize_msp_attribute_bn_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<MSPAttribute, bn_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        MSPAttribute key = deserialize_msp_attribute<ATTR_TYPE, OCCUR_TYPE>(data, offset_ptr);
        auto value = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*value);
        deserialize_bn_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of MSPAttributes to g1_t values to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value of the MSPAttributes.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count of the MSPAttributes.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_msp_attribute_g1_t_map(std::vector<unsigned char>& data, const std::map<MSPAttribute, g1_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_msp_attribute<ATTR_TYPE, OCCUR_TYPE>(data, k);
        serialize_g1_t(data, *v);
    }
}

/**
 * Deserializes a map of MSPAttributes to g1_t values from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value of the MSPAttributes.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count of the MSPAttributes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<MSPAttribute, g1_t *> deserialize_msp_attribute_g1_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<MSPAttribute, g1_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        MSPAttribute key = deserialize_msp_attribute<ATTR_TYPE, OCCUR_TYPE>(data, offset_ptr);
        auto value = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*value);
        deserialize_g1_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of MSPAttributes to g2_t values to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value of the MSPAttributes.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count of the MSPAttributes.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_msp_attribute_g2_t_map(std::vector<unsigned char>& data, const std::map<MSPAttribute, g2_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_msp_attribute<ATTR_TYPE, OCCUR_TYPE>(data, k);
        serialize_g2_t(data, *v);
    }
}

/**
 * Deserializes a map of MSPAttributes to g2_t values from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value of the MSPAttributes.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count of the MSPAttributes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<MSPAttribute, g2_t *> deserialize_msp_attribute_g2_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<MSPAttribute, g2_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        MSPAttribute key = deserialize_msp_attribute<ATTR_TYPE, OCCUR_TYPE>(data, offset_ptr);
        auto value = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*value);
        deserialize_g2_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of MSPAttributes to gt_t values to bytes.
 * @tparam ATTR_TYPE the type of integer used to serialize the attribute value of the MSPAttributes.
 * @tparam OCCUR_TYPE the type of integer used to serialize the occurrence count of the MSPAttributes.
 * @tparam SIZE_TYPE the type of integer used to serialize the map size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
void serialize_msp_attribute_gt_t_map(std::vector<unsigned char>& data, const std::map<MSPAttribute, gt_t *>& map) {
    const SIZE_TYPE length = map.size();
    serialize_int<SIZE_TYPE>(data, length);
    for (const auto& [k, v] : map) {
        serialize_msp_attribute<ATTR_TYPE, OCCUR_TYPE>(data, k);
        serialize_gt_t(data, *v);
    }
}

/**
 * Deserializes a map of MSPAttributes to gt_t values from bytes.
 * @tparam ATTR_TYPE the type of integer used to deserialize the attribute value of the MSPAttributes.
 * @tparam OCCUR_TYPE the type of integer used to deserialize the occurrence count of the MSPAttributes.
 * @tparam SIZE_TYPE the type of integer used to deserialize the map size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename ATTR_TYPE, typename OCCUR_TYPE, typename SIZE_TYPE,
std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<OCCUR_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<SIZE_TYPE>, bool> = true>
std::map<MSPAttribute, gt_t *> deserialize_msp_attribute_gt_t_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const SIZE_TYPE length = deserialize_int<SIZE_TYPE>(data, offset_ptr);
    std::map<MSPAttribute, gt_t *> result;
    for (SIZE_TYPE i = 0; i < length; ++i) {
        MSPAttribute key = deserialize_msp_attribute<ATTR_TYPE, OCCUR_TYPE>(data, offset_ptr);
        auto value = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*value);
        deserialize_gt_t(*value, data, offset_ptr);
        result[key] = value;
    }
    return result;
}

/**
 * Serializes a map of integers to vectors of bn_t values to bytes.
 * Important: All vectors have the same length!
 * @tparam KEY_TYPE the type of integer used to serialize the map keys.
 * @tparam MAP_SIZE_TYPE the type of integer used to serialize the map size.
 * @tparam VECTOR_SIZE_TYPE the type of integer used to serialize the vector size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename KEY_TYPE, typename MAP_SIZE_TYPE, typename VECTOR_SIZE_TYPE,
std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<MAP_SIZE_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<VECTOR_SIZE_TYPE>, bool> = true>
void serialize_int_bn_t_vector_map(std::vector<unsigned char>& data, const std::map<KEY_TYPE, std::vector<bn_t *>>& map) {
    const MAP_SIZE_TYPE map_length = map.size();
    serialize_int<MAP_SIZE_TYPE>(data, map_length);
    const VECTOR_SIZE_TYPE vector_length = map.begin()->second.size();
    serialize_int<VECTOR_SIZE_TYPE>(data, vector_length);
    for (auto [k, vec] : map) {
        serialize_int<KEY_TYPE>(data, k);
        for (auto val : vec) {
            serialize_bn_t(data, *val);
        }
    }
}

/**
 * Deserializes a map of integers to vectors of bn_t values from bytes.
 * Important: All vectors have the same length!
 * @tparam KEY_TYPE the type of integer used to deserialize the map keys.
 * @tparam MAP_SIZE_TYPE the type of integer used to deserialize the map size.
 * @tparam VECTOR_SIZE_TYPE the type of integer used to deserialize the vector size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename KEY_TYPE, typename MAP_SIZE_TYPE, typename VECTOR_SIZE_TYPE,
std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<MAP_SIZE_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<VECTOR_SIZE_TYPE>, bool> = true>
std::map<KEY_TYPE, std::vector<bn_t *>> deserialize_int_bn_t_vector_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const MAP_SIZE_TYPE map_length = deserialize_int<MAP_SIZE_TYPE>(data, offset_ptr);
    const VECTOR_SIZE_TYPE vector_length = deserialize_int<VECTOR_SIZE_TYPE>(data, offset_ptr);
    std::map<KEY_TYPE, std::vector<bn_t *>> result;
    for (MAP_SIZE_TYPE i = 0; i < map_length; ++i) {
        KEY_TYPE key = deserialize_int<KEY_TYPE>(data, offset_ptr);
        std::vector<bn_t *> vec(vector_length);
        for (VECTOR_SIZE_TYPE j = 0; j < vector_length; ++j) {
            auto value = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*value);
            deserialize_bn_t(*value, data, offset_ptr);
            vec[j] = value;
        }
        result[key] = vec;
    }
    return result;
}

/**
 * Serializes a map of integers to vectors of g1_t values to bytes.
 * Important: All vectors have the same length!
 * @tparam KEY_TYPE the type of integer used to serialize the map keys.
 * @tparam MAP_SIZE_TYPE the type of integer used to serialize the map size.
 * @tparam VECTOR_SIZE_TYPE the type of integer used to serialize the vector size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename KEY_TYPE, typename MAP_SIZE_TYPE, typename VECTOR_SIZE_TYPE,
std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<MAP_SIZE_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<VECTOR_SIZE_TYPE>, bool> = true>
void serialize_int_g1_t_vector_map(std::vector<unsigned char>& data, const std::map<KEY_TYPE, std::vector<g1_t *>>& map) {
    const MAP_SIZE_TYPE map_length = map.size();
    serialize_int<MAP_SIZE_TYPE>(data, map_length);
    const VECTOR_SIZE_TYPE vector_length = map.begin()->second.size();
    serialize_int<VECTOR_SIZE_TYPE>(data, vector_length);
    for (auto [k, vec] : map) {
        serialize_int<KEY_TYPE>(data, k);
        for (auto val : vec) {
            serialize_g1_t(data, *val);
        }
    }
}

/**
 * Deserializes a map of integers to vectors of g1_t values from bytes.
 * Important: All vectors have the same length!
 * @tparam KEY_TYPE the type of integer used to deserialize the map keys.
 * @tparam MAP_SIZE_TYPE the type of integer used to deserialize the map size.
 * @tparam VECTOR_SIZE_TYPE the type of integer used to deserialize the vector size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename KEY_TYPE, typename MAP_SIZE_TYPE, typename VECTOR_SIZE_TYPE,
std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<MAP_SIZE_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<VECTOR_SIZE_TYPE>, bool> = true>
std::map<KEY_TYPE, std::vector<g1_t *>> deserialize_int_g1_t_vector_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const MAP_SIZE_TYPE map_length = deserialize_int<MAP_SIZE_TYPE>(data, offset_ptr);
    const VECTOR_SIZE_TYPE vector_length = deserialize_int<VECTOR_SIZE_TYPE>(data, offset_ptr);
    std::map<KEY_TYPE, std::vector<g1_t *>> result;
    for (MAP_SIZE_TYPE i = 0; i < map_length; ++i) {
        KEY_TYPE key = deserialize_int<KEY_TYPE>(data, offset_ptr);
        std::vector<g1_t *> vec(vector_length);
        for (VECTOR_SIZE_TYPE j = 0; j < vector_length; ++j) {
            auto value = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*value);
            deserialize_g1_t(*value, data, offset_ptr);
            vec[j] = value;
        }
        result[key] = vec;
    }
    return result;
}

/**
 * Serializes a map of integers to vectors of g2_t values to bytes.
 * Important: All vectors have the same length!
 * @tparam KEY_TYPE the type of integer used to serialize the map keys.
 * @tparam MAP_SIZE_TYPE the type of integer used to serialize the map size.
 * @tparam VECTOR_SIZE_TYPE the type of integer used to serialize the vector size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename KEY_TYPE, typename MAP_SIZE_TYPE, typename VECTOR_SIZE_TYPE,
std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<MAP_SIZE_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<VECTOR_SIZE_TYPE>, bool> = true>
void serialize_int_g2_t_vector_map(std::vector<unsigned char>& data, const std::map<KEY_TYPE, std::vector<g2_t *>>& map) {
    const MAP_SIZE_TYPE map_length = map.size();
    serialize_int<MAP_SIZE_TYPE>(data, map_length);
    const VECTOR_SIZE_TYPE vector_length = map.begin()->second.size();
    serialize_int<VECTOR_SIZE_TYPE>(data, vector_length);
    for (auto [k, vec] : map) {
        serialize_int<KEY_TYPE>(data, k);
        for (auto val : vec) {
            serialize_g2_t(data, *val);
        }
    }
}

/**
 * Deserializes a map of integers to vectors of g2_t values from bytes.
 * Important: All vectors have the same length!
 * @tparam KEY_TYPE the type of integer used to deserialize the map keys.
 * @tparam MAP_SIZE_TYPE the type of integer used to deserialize the map size.
 * @tparam VECTOR_SIZE_TYPE the type of integer used to deserialize the vector size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename KEY_TYPE, typename MAP_SIZE_TYPE, typename VECTOR_SIZE_TYPE,
std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<MAP_SIZE_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<VECTOR_SIZE_TYPE>, bool> = true>
std::map<KEY_TYPE, std::vector<g2_t *>> deserialize_int_g2_t_vector_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const MAP_SIZE_TYPE map_length = deserialize_int<MAP_SIZE_TYPE>(data, offset_ptr);
    const VECTOR_SIZE_TYPE vector_length = deserialize_int<VECTOR_SIZE_TYPE>(data, offset_ptr);
    std::map<KEY_TYPE, std::vector<g2_t *>> result;
    for (MAP_SIZE_TYPE i = 0; i < map_length; ++i) {
        KEY_TYPE key = deserialize_int<KEY_TYPE>(data, offset_ptr);
        std::vector<g2_t *> vec(vector_length);
        for (VECTOR_SIZE_TYPE j = 0; j < vector_length; ++j) {
            auto value = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*value);
            deserialize_g2_t(*value, data, offset_ptr);
            vec[j] = value;
        }
        result[key] = vec;
    }
    return result;
}

/**
 * Serializes a map of integers to vectors of gt_t values to bytes.
 * Important: All vectors have the same length!
 * @tparam KEY_TYPE the type of integer used to serialize the map keys.
 * @tparam MAP_SIZE_TYPE the type of integer used to serialize the map size.
 * @tparam VECTOR_SIZE_TYPE the type of integer used to serialize the vector size.
 * @param[out] data the bytes are appended to this vector.
 * @param[in] map the map to serialize.
 */
template<typename KEY_TYPE, typename MAP_SIZE_TYPE, typename VECTOR_SIZE_TYPE,
std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<MAP_SIZE_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<VECTOR_SIZE_TYPE>, bool> = true>
void serialize_int_gt_t_vector_map(std::vector<unsigned char>& data, const std::map<KEY_TYPE, std::vector<gt_t *>>& map) {
    const MAP_SIZE_TYPE map_length = map.size();
    serialize_int<MAP_SIZE_TYPE>(data, map_length);
    const VECTOR_SIZE_TYPE vector_length = map.begin()->second.size();
    serialize_int<VECTOR_SIZE_TYPE>(data, vector_length);
    for (auto [k, vec] : map) {
        serialize_int<KEY_TYPE>(data, k);
        for (auto val : vec) {
            serialize_gt_t(data, *val);
        }
    }
}

/**
 * Deserializes a map of integers to vectors of gt_t values from bytes.
 * Important: All vectors have the same length!
 * @tparam KEY_TYPE the type of integer used to deserialize the map keys.
 * @tparam MAP_SIZE_TYPE the type of integer used to deserialize the map size.
 * @tparam VECTOR_SIZE_TYPE the type of integer used to deserialize the vector size.
 * @param[in] data the bytes are contained in this vector.
 * @param[in,out] offset_ptr a pointer to an integer that contains the position of the map in `data`. This
 *      value is incremented by the size of the serialized map in bytes.
 * @returns the deserialized map.
 */
template<typename KEY_TYPE, typename MAP_SIZE_TYPE, typename VECTOR_SIZE_TYPE,
std::enable_if_t<std::is_integral_v<KEY_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<MAP_SIZE_TYPE>, bool> = true,
std::enable_if_t<std::is_integral_v<VECTOR_SIZE_TYPE>, bool> = true>
std::map<KEY_TYPE, std::vector<gt_t *>> deserialize_int_gt_t_vector_map(const std::vector<unsigned char>& data, int *offset_ptr) {
    const MAP_SIZE_TYPE map_length = deserialize_int<MAP_SIZE_TYPE>(data, offset_ptr);
    const VECTOR_SIZE_TYPE vector_length = deserialize_int<VECTOR_SIZE_TYPE>(data, offset_ptr);
    std::map<KEY_TYPE, std::vector<gt_t *>> result;
    for (MAP_SIZE_TYPE i = 0; i < map_length; ++i) {
        KEY_TYPE key = deserialize_int<KEY_TYPE>(data, offset_ptr);
        std::vector<gt_t *> vec(vector_length);
        for (VECTOR_SIZE_TYPE j = 0; j < vector_length; ++j) {
            auto value = static_cast<gt_t *>(malloc(sizeof(gt_t)));
            gt_util_null_init(*value);
            deserialize_gt_t(*value, data, offset_ptr);
            vec[j] = value;
        }
        result[key] = vec;
    }
    return result;
}

#endif //MASTER_SERIALIZE_H

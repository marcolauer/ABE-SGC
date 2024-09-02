#ifndef MASTER_CPABE_H
#define MASTER_CPABE_H

#include <vector>
#include <map>
#include "../TTree.h"
#include "../serialize.h"
#include "../relic_util.h"
extern "C" {
#include <relic.h>
}

/**
 * The CP-ABE scheme by Bethencourt et al.
 * (<a href="https://www.cs.utexas.edu/~bwaters/publications/papers/cp-abe.pdf">Link</a>). Converted for type-3
 * pairings. With optimizations from the same paper.
 */
namespace cpabe {
    struct master_key {
        bn_t *beta_inv{};
        g1_t *g_alpha{};
    };

    struct public_key {
        g2_t *h{};
        gt_t *egg_alpha{};
    };

    struct secret_key {
        std::vector<int> identity;
        g1_t *D{};
        std::map<int, g2_t *> Ds;
        std::map<int, g1_t *> Dprimes;
    };

    struct ciphertext {
        TTree *policy{};
        gt_t *C_circum{};
        g2_t *C{};
        std::map<TAttribute, g1_t *> Cs;
        std::map<TAttribute, g2_t *> Cprimes;
    };


    /**
     * Runs the setup algorithm of the CP-ABE scheme.
     * @param[out] mk the ABE master key.
     * @param[out] pk the ABE public key.
     * @param[in] order the order of the finite field Z_p.
     */
    void setup(master_key& mk, public_key& pk, bn_t order);

    /**
     * Runs the key generation algorithm of the CP-ABE scheme.
     * @param[out] sk the ABE secret key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] identity the identity for the ABE secret key.
     * @param[in] mk the ABE master key.
     */
    void key_generation(secret_key& sk, bn_t order, const std::vector<int>& identity, const master_key& mk);

    /**
     * Runs the encryption algorithm of the CP-ABE scheme.
     * @param[out] ct the ABE ciphertext.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] message the message to encrypt (an element of G_T).
     * @param[in] policy the access structure for the ABE ciphertext.
     * @param[in] pk the ABE public key.
     */
    void encryption(ciphertext& ct, bn_t order, gt_t message, TTree *policy, const public_key& pk);

    /**
     * Runs the decryption algorithm of the CP-ABE scheme.
     * @param[out] message the decrypted message (an element of G_T).
     * @param[in] order the order of the finite field Z_p.
     * @param[in] ct the ABE ciphertext.
     * @param[in] sk the ABE secret key.
     */
    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk);


    /**
     * Frees the allocated content in the ABE master key data structure of the CP-ABE scheme.
     * @param[out] mk the (empty) ABE master key.
     */
    void free_master_key(const master_key& mk);

    /**
     * Frees the allocated content in the ABE public key data structure of the CP-ABE scheme.
     * @param[out] pk the (empty) ABE public key.
     */
    void free_public_key(const public_key& pk);

    /**
     * Frees the allocated content in the ABE secret key data structure of the CP-ABE scheme.
     * @param[out] sk the (empty) ABE secret key.
     */
    void free_secret_key(secret_key& sk);

    /**
     * Frees the allocated content in the ABE ciphertext data structure of the CP-ABE scheme.
     * @param[out] ct the (empty) ABE ciphertext.
     */
    void free_ciphertext(ciphertext& ct);


    /**
     * Serializes the ABE master key data structure of the CP-ABE scheme to bytes.
     * @param[out] data the serialized ABE master key is appended to this vector of bytes.
     * @param[in] mk the ABE master key.
     */
    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk);

    /**
     * Deserializes the ABE master key data structure of the CP-ABE scheme from bytes.
     * @param[in] data the vector of bytes from which the ABE master key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE master key start in "data".
     *      The offset is incremented by the size of the ABE master key in bytes.
     * @returns the ABE master key.
     */
    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr);

    /**
     * Serializes the ABE public key data structure of the CP-ABE scheme to bytes.
     * @param[out] data the serialized ABE public key is appended to this vector of bytes.
     * @param[in] pk the ABE public key.
     */
    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk);

    /**
     * Deserializes the ABE public key data structure of the CP-ABE scheme from bytes.
     * @param[in] data the vector of bytes from which the ABE public key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE public key start in "data".
     *      The offset is incremented by the size of the ABE public key in bytes.
     * @returns the ABE public key.
     */
    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr);

    /**
     * Serializes the ABE secret key data structure of the CP-ABE scheme to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE secret key is appended to this vector of bytes.
     * @param[in] sk the ABE secret key.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void serialize_sk(std::vector<unsigned char>& data, const secret_key& sk) {
        const std::vector<ATTR_TYPE> identity(sk.identity.begin(), sk.identity.end());
        serialize_int_vector<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, identity);
        serialize_g1_t(data, *sk.D);
        const std::map<ATTR_TYPE, g2_t *> Ds(sk.Ds.begin(), sk.Ds.end());
        serialize_int_g2_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, Ds);
        const std::map<ATTR_TYPE, g1_t *> Dprimes(sk.Dprimes.begin(), sk.Dprimes.end());
        serialize_int_g1_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, Dprimes);
    }

    /**
     * Deserializes the ABE secret key data structure of the CP-ABE scheme from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABE secret key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE secret key start in "data".
     *      The offset is incremented by the size of the ABE secret key in bytes.
     * @returns the ABE secret key.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    secret_key deserialize_sk(const std::vector<unsigned char>& data, int *offset_ptr) {
        secret_key sk;
        std::vector<ATTR_TYPE> identity = deserialize_int_vector<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        sk.identity = std::vector<int>(identity.begin(), identity.end());
        sk.D = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*sk.D);
        deserialize_g1_t(*sk.D, data, offset_ptr);
        std::map<ATTR_TYPE, g2_t *> Ds = deserialize_int_g2_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        sk.Ds = std::map<int, g2_t *>(Ds.begin(), Ds.end());
        std::map<ATTR_TYPE, g1_t *> Dprimes = deserialize_int_g1_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        sk.Dprimes = std::map<int, g1_t *>(Dprimes.begin(), Dprimes.end());
        return sk;
    }

    /**
     * Serializes the ABE ciphertext data structure of the CP-ABE scheme to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE ciphertext is appended to this vector of bytes.
     * @param[in] ct the ABE ciphertext.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void serialize_ct(std::vector<unsigned char>& data, const ciphertext& ct) {
        serialize_ttree_policy<ATTR_TYPE, ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, ct.policy);
        serialize_gt_t(data, *ct.C_circum);
        serialize_g2_t(data, *ct.C);
        serialize_tattribute_g1_t_map<ATTR_TYPE, ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, ct.Cs);
        serialize_tattribute_g2_t_map<ATTR_TYPE, ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, ct.Cprimes);
    }

    /**
     * Deserializes the ABE ciphertext data structure of the CP-ABE scheme from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABE ciphertext is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE ciphertext start in "data".
     *      The offset is incremented by the size of the ABE ciphertext in bytes.
     * @returns the ABE ciphertext.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    ciphertext deserialize_ct(const std::vector<unsigned char>& data, int *offset_ptr) {
        ciphertext ct;
        ct.policy = deserialize_ttree_policy<ATTR_TYPE, ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        ct.C_circum = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ct.C_circum);
        deserialize_gt_t(*ct.C_circum, data, offset_ptr);
        ct.C = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*ct.C);
        deserialize_g2_t(*ct.C, data, offset_ptr);
        ct.Cs = deserialize_tattribute_g1_t_map<ATTR_TYPE, ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        ct.Cprimes = deserialize_tattribute_g2_t_map<ATTR_TYPE, ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        return ct;
    }
}
#endif //MASTER_CPABE_H

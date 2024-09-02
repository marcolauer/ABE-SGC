#ifndef MASTER_FAME_KPABE_H
#define MASTER_FAME_KPABE_H

#include <vector>
#include <map>
#include "../TTree.h"
#include "../serialize.h"
extern "C" {
#include <relic.h>
}

/**
 * The FAME KP-ABE scheme by Agrawal and Chase (<a href="https://eprint.iacr.org/2017/807">Link</a>).
 */
namespace fame_kpabe {
    struct master_key {
        std::vector<bn_t *> as{};
        std::vector<bn_t *> bs{};
        std::vector<g1_t *> g_ds{};
    };

    struct public_key {
        int assump_size{};
        std::vector<g2_t *> Hs{};
        std::vector<gt_t *> Ts{};
    };

    struct secret_key {
        int assump_size{};
        TTree *policy{};
        std::vector<g2_t *> sk0;
        std::map<int, std::vector<g1_t *>> sk;
    };

    struct ciphertext {
        std::vector<int> identity;
        std::vector<g2_t *> ct0{};
        std::map<int, std::vector<g1_t *>> ct;
        gt_t *ctprime{};
    };


    /**
     * Runs the setup algorithm of the FAME KP-ABE scheme.
     * @param[out] mk the ABE master key.
     * @param[out] pk the ABE public key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] assump_size the security parameter for the hardness assumption of the FAME ABE schemes.
     */
    void setup(master_key& mk, public_key& pk, bn_t order, int assump_size);

    /**
     * Runs the key generation algorithm of the FAME KP-ABE scheme.
     * @param[out] sk the ABE secret key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] policy the access structure for the ABE secret key.
     * @param[in] pk the ABE public key.
     * @param[in] mk the ABE master key.
     */
    void key_generation(secret_key& sk, bn_t order, TTree *policy, const public_key& pk, const master_key& mk);

    /**
     * Runs the encryption algorithm of the FAME KP-ABE scheme.
     * @param[out] ct the ABE ciphertext.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] message the message to encrypt (an element of G_T).
     * @param[in] identity the identity for the ABE ciphertext.
     * @param[in] pk the ABE public key.
     */
    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& identity, const public_key& pk);

    /**
     * Runs the decryption algorithm of the FAME KP-ABE scheme.
     * @param[out] message the decrypted message (an element of G_T).
     * @param[in] order the order of the finite field Z_p.
     * @param[in] ct the ABE ciphertext.
     * @param[in] sk the ABE secret key.
     */
    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk);


    /**
     * Frees the allocated content in the ABE master key data structure of the FAME KP-ABE scheme.
     * @param[out] mk the (empty) ABE master key.
     */
    void free_master_key(master_key& mk);

    /**
     * Frees the allocated content in the ABE public key data structure of the FAME KP-ABE scheme.
     * @param[out] pk the (empty) ABE public key.
     */
    void free_public_key(public_key& pk);

    /**
     * Frees the allocated content in the ABE secret key data structure of the FAME KP-ABE scheme.
     * @param[out] sk the (empty) ABE secret key.
     */
    void free_secret_key(secret_key& sk);

    /**
     * Frees the allocated content in the ABE ciphertext data structure of the FAME KP-ABE scheme.
     * @param[out] ct the (empty) ABE ciphertext.
     */
    void free_ciphertext(ciphertext& ct);


    /**
     * Serializes the ABE master key data structure of the FAME KP-ABE scheme to bytes.
     * @param[out] data the serialized ABE master key is appended to this vector of bytes.
     * @param[in] mk the ABE master key.
     */
    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk);

    /**
     * Deserializes the ABE master key data structure of the FAME KP-ABE scheme from bytes.
     * @param[in] data the vector of bytes from which the ABE master key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE master key start in "data".
     *      The offset is incremented by the size of the ABE master key in bytes.
     * @returns the ABE master key.
     */
    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr);

    /**
     * Serializes the ABE public key data structure of the FAME KP-ABE scheme to bytes.
     * @param[out] data the serialized ABE public key is appended to this vector of bytes.
     * @param[in] pk the ABE public key.
     */
    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk);

    /**
     * Deserializes the ABE public key data structure of the FAME KP-ABE scheme from bytes.
     * @param[in] data the vector of bytes from which the ABE public key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE public key start in "data".
     *      The offset is incremented by the size of the ABE public key in bytes.
     * @returns the ABE public key.
     */
    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr);

    /**
     * Serializes the ABE secret key data structure of the FAME KP-ABE scheme to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE secret key is appended to this vector of bytes.
     * @param[in] sk the ABE secret key.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void serialize_sk(std::vector<unsigned char>& data, const secret_key& sk) {
        serialize_int<uint8_t>(data, sk.assump_size);
        serialize_ttree_policy<ATTR_TYPE, ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, sk.policy);
        serialize_g2_t_vector<uint8_t>(data, sk.sk0);
        const std::map<ATTR_TYPE, std::vector<g1_t *>> sk_map(sk.sk.begin(), sk.sk.end());
        serialize_int_g1_t_vector_map<ATTR_TYPE, IDENTITY_SIZE_TYPE, uint8_t>(data, sk_map);
    }

    /**
     * Deserializes the ABE secret key data structure of the FAME KP-ABE scheme from bytes.
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
        sk.assump_size = deserialize_int<uint8_t>(data, offset_ptr);
        sk.policy = deserialize_ttree_policy<ATTR_TYPE, ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        sk.sk0 = deserialize_g2_t_vector<uint8_t>(data, offset_ptr);
        const std::map<ATTR_TYPE, std::vector<g1_t *>> sk_map = deserialize_int_g1_t_vector_map<ATTR_TYPE, IDENTITY_SIZE_TYPE, uint8_t>(data, offset_ptr);
        sk.sk = std::map<int, std::vector<g1_t *>>(sk_map.begin(), sk_map.end());
        return sk;
    }

    /**
     * Serializes the ABE ciphertext data structure of the FAME KP-ABE scheme to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE ciphertext is appended to this vector of bytes.
     * @param[in] ct the ABE ciphertext.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void serialize_ct(std::vector<unsigned char>& data, const ciphertext& ct) {
        const std::vector<ATTR_TYPE> identity(ct.identity.begin(), ct.identity.end());
        serialize_int_vector<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, identity);
        serialize_g2_t_vector<uint8_t>(data, ct.ct0);
        const std::map<ATTR_TYPE, std::vector<g1_t *>> ct_map(ct.ct.begin(), ct.ct.end());
        serialize_int_g1_t_vector_map<ATTR_TYPE, IDENTITY_SIZE_TYPE, uint8_t>(data, ct_map);
        serialize_gt_t(data, *ct.ctprime);
    }

    /**
     * Deserializes the ABE ciphertext data structure of the FAME KP-ABE scheme from bytes.
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
        const std::vector<ATTR_TYPE> identity = deserialize_int_vector<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        ct.identity = std::vector<int>(identity.begin(), identity.end());
        ct.ct0 = deserialize_g2_t_vector<uint8_t>(data, offset_ptr);
        const std::map<ATTR_TYPE, std::vector<g1_t *>> ct_map = deserialize_int_g1_t_vector_map<ATTR_TYPE, IDENTITY_SIZE_TYPE, uint8_t>(data, offset_ptr);
        ct.ct = std::map<int, std::vector<g1_t *>>(ct_map.begin(), ct_map.end());
        ct.ctprime = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ct.ctprime);
        deserialize_gt_t(*ct.ctprime, data, offset_ptr);
        return ct;
    }
}

#endif //MASTER_FAME_KPABE_H

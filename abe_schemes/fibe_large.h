#ifndef MASTER_FIBE_LARGE_H
#define MASTER_FIBE_LARGE_H

#include <vector>
#include <map>
#include "../serialize.h"
extern "C" {
#include <relic.h>
}

/**
 * The large universe construction of the Fuzzy-IBE scheme by Sahai and Waters
 * (<a href="https://eprint.iacr.org/2004/086.pdf">Link</a>). Converted for type-3 pairings.
 */
namespace fibe_large {
    struct master_key {
        bn_t *y{};
    };

    struct public_key {
        g1_t *g1{};
        g2_t *g2{};
        int n{};
        std::vector<g2_t *> ts;
    };

    struct secret_key {
        std::vector<int> identity;
        int d{};
        std::map<int, g2_t *> Ds;
        std::map<int, g1_t *> ds;
    };

    struct ciphertext {
        std::vector<int> identity;
        gt_t *Eprime{};
        g1_t *Eprimeprime{};
        std::map<int, g2_t *> Es;
    };

    /**
     * Runs the setup algorithm of the large universe Fuzzy-IBE scheme.
     * @param[out] mk the ABE master key.
     * @param[out] pk the ABE public key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] n the maximum size of the identities.
     */
    void setup(master_key& mk, public_key& pk, bn_t order, int n);

    /**
     * Runs the key generation algorithm of the large universe Fuzzy-IBE scheme.
     * @param[out] sk the ABE secret key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] d the threshold value of the threshold gate access structure for the ABE secret key.
     * @param[in] identity the attributes of the threshold gate access structure for the ABE secret key.
     * @param[in] pk the ABE public key.
     * @param[in] mk the ABE master key.
     */
    void key_generation(secret_key& sk, bn_t order, int d, const std::vector<int>& identity, const public_key& pk,
                        const master_key& mk);

    /**
     * Runs the encryption algorithm of the large universe Fuzzy-IBE scheme.
     * @param[out] ct the ABE ciphertext.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] message the message to encrypt (an element of G_T).
     * @param[in] identity the identity for the ABE ciphertext.
     * @param[in] pk the ABE public key.
     */
    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& identity, const public_key& pk);

    /**
     * Runs the decryption algorithm of the large universe Fuzzy-IBE scheme.
     * @param[out] message the decrypted message (an element of G_T).
     * @param[in] order the order of the finite field Z_p.
     * @param[in] ct the ABE ciphertext.
     * @param[in] sk the ABE secret key.
     */
    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk);


    /**
     * Frees the allocated content in the ABE master key data structure of the large universe Fuzzy-IBE scheme.
     * @param[out] mk the (empty) ABE master key.
     */
    void free_master_key(const master_key& mk);

    /**
     * Frees the allocated content in the ABE public key data structure of the large universe Fuzzy-IBE scheme.
     * @param[out] pk the (empty) ABE public key.
     */
    void free_public_key(public_key& pk);

    /**
     * Frees the allocated content in the ABE secret key data structure of the large universe Fuzzy-IBE scheme.
     * @param[out] sk the (empty) ABE secret key.
     */
    void free_secret_key(secret_key& sk);

    /**
     * Frees the allocated content in the ABE ciphertext data structure of the large universe Fuzzy-IBE scheme.
     * @param[out] ct the (empty) ABE ciphertext.
     */
    void free_ciphertext(ciphertext& ct);


    /**
     * Serializes the ABE master key data structure of the large universe Fuzzy-IBE scheme to bytes.
     * @param[out] data the serialized ABE master key is appended to this vector of bytes.
     * @param[in] mk the ABE master key.
     */
    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk);

    /**
     * Deserializes the ABE master key data structure of the large universe Fuzzy-IBE scheme from bytes.
     * @param[in] data the vector of bytes from which the ABE master key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE master key start in "data".
     *      The offset is incremented by the size of the ABE master key in bytes.
     * @returns the ABE master key.
     */
    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr);

    /**
     * Serializes the ABE public key data structure of the large universe Fuzzy-IBE scheme to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE public key is appended to this vector of bytes.
     * @param[in] pk the ABE public key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk) {
        serialize_g1_t(data, *pk.g1);
        serialize_g2_t(data, *pk.g2);
        serialize_int<ATTR_TYPE>(data, pk.n);
        serialize_g2_t_vector<ATTR_TYPE>(data, pk.ts);
    }

    /**
     * Deserializes the ABE public key data structure of the large universe Fuzzy-IBE scheme from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABE public key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE public key start in "data".
     *      The offset is incremented by the size of the ABE public key in bytes.
     * @returns the ABE public key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr) {
        public_key pk;
        pk.g1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*pk.g1);
        deserialize_g1_t(*pk.g1, data, offset_ptr);
        pk.g2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*pk.g2);
        deserialize_g2_t(*pk.g2, data, offset_ptr);
        pk.n = deserialize_int<ATTR_TYPE>(data, offset_ptr);
        pk.ts = deserialize_g2_t_vector<ATTR_TYPE>(data, offset_ptr);
        return pk;
    }

    /**
     * Serializes the ABE secret key data structure of the large universe Fuzzy-IBE scheme to bytes.
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
        serialize_int<IDENTITY_SIZE_TYPE>(data, sk.d);
        const std::map<ATTR_TYPE, g2_t *> Ds(sk.Ds.begin(), sk.Ds.end());
        serialize_int_g2_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, Ds);
        const std::map<ATTR_TYPE, g1_t *> ds(sk.ds.begin(), sk.ds.end());
        serialize_int_g1_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, ds);
    }

    /**
     * Deserializes the ABE secret key data structure of the large universe Fuzzy-IBE scheme from bytes.
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
        sk.d = deserialize_int<IDENTITY_SIZE_TYPE>(data, offset_ptr);
        std::map<ATTR_TYPE, g2_t *> Ds = deserialize_int_g2_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        sk.Ds = std::map<int, g2_t *>(Ds.begin(), Ds.end());
        std::map<ATTR_TYPE, g1_t *> ds = deserialize_int_g1_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        sk.ds = std::map<int, g1_t *>(ds.begin(), ds.end());
        return sk;
    }

    /**
     * Serializes the ABE ciphertext data structure of the large universe Fuzzy-IBE scheme to bytes.
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
        serialize_gt_t(data, *ct.Eprime);
        serialize_g1_t(data, *ct.Eprimeprime);
        const std::map<ATTR_TYPE, g2_t *> Es(ct.Es.begin(), ct.Es.end());
        serialize_int_g2_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, Es);
    }

    /**
     * Deserializes the ABE ciphertext data structure of the large universe Fuzzy-IBE scheme from bytes.
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
        std::vector<ATTR_TYPE> identity = deserialize_int_vector<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        ct.identity = std::vector<int>(identity.begin(), identity.end());
        ct.Eprime = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ct.Eprime);
        deserialize_gt_t(*ct.Eprime, data, offset_ptr);
        ct.Eprimeprime = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*ct.Eprimeprime);
        deserialize_g1_t(*ct.Eprimeprime, data, offset_ptr);
        std::map<ATTR_TYPE, g2_t *> Es = deserialize_int_g2_t_map<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        ct.Es = std::map<int, g2_t *>(Es.begin(), Es.end());
        return ct;
    }
}

#endif //MASTER_FIBE_LARGE_H

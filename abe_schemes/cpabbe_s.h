#ifndef MASTER_CPABBE_S_H
#define MASTER_CPABBE_S_H

#include <vector>
#include "../serialize.h"
extern "C" {
#include <relic.h>
}

/**
  * The KP-ABBE scheme by Phuong et al. (<a href="http://dx.doi.org/10.1007/978-3-319-24177-7_13">Link</a>).
 * Converted for type-3 pairings. Implementation with swapped groups G_1 and G_2.
 */
namespace cpabbe_s {
    struct master_key {
        bn_t *alpha{};
        bn_t *gamma{};
        bn_t *delta{};
        bn_t *theta{};
    };

    struct public_key {
        int n; // Number of attributes in an access structure
        int N1;
        std::vector<g2_t *> gs_g2;
        std::vector<g1_t *> gs_g1;
        std::vector<g2_t *> hs_g2;
        std::vector<g1_t *> hs_g1;
        g1_t *ny;
        g1_t *v0;
        g1_t *v1;
    };

    struct secret_key {
        int id;
        int n;
        std::vector<g2_t *> gs_g2;
        g2_t *D1{};
        g2_t *D2{};
        g2_t *D3{};
        std::vector<g2_t *> D4s;
        std::vector<g2_t *> D5s;
    };

    struct ciphertext {
        std::vector<int> S;
        std::vector<int> J;
        gt_t *C0{};
        g1_t *C1;
        g1_t *C2;
        g1_t *C3;
        g1_t *C4;
    };


    /**
     * Runs the setup algorithm of the CP-ABBE scheme.
     * @param[out] mk the ABBE master key.
     * @param[out] pk the ABBE public key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] n the limit to the number of user ids and attributes.
     * @param[in] N the limit to the number of attributes (N <= n).
     * @param[in] N1 the limit to the number of wildcards in the access structures.
     */
    void setup(master_key& mk, public_key& pk, bn_t order, int n, int N, int N1);

    /**
     * Runs the key generation algorithm of the CP-ABBE scheme.
     * @param[out] sk the ABBE secret key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] id the id of the owner of the secret key.
     * @param[in] V the positive attributes of the identity for the ABBE secret key.
     * @param[in] Z the negative attributes of the identity for the ABBE secret key.
     * @param[in] pk the ABBE public key.
     * @param[in] mk the ABBE master key.
     */
    void key_generation(secret_key& sk, bn_t order, int id, const std::vector<int>& V, const std::vector<int>& Z,
                        const public_key& pk, const master_key& mk);

    /**
     * Runs the encryption algorithm of the CP-ABBE scheme.
     * @param[out] ct the ABBE ciphertext.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] message the message to encrypt (an element of G_T).
     * @param[in] S the set of user ids that are allowed to decrypt.
     * @param[in] J the wildcard attributes of the access structure for the ABBE ciphertext.
     * @param[in] V the positive attributes of the access structure for the ABBE ciphertext.
     * @param[in] Z the negative attributes of the access structure for the ABBE ciphertext.
     * @param[in] pk the ABBE public key.
     */
    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& S, const std::vector<int>& J,
                    const std::vector<int>& V, const std::vector<int>& Z, const public_key& pk);

    /**
     * Runs the decryption algorithm of the CP-ABBE scheme.
     * @param[out] message the decrypted message (an element of G_T).
     * @param[in] order the order of the finite field Z_p.
     * @param[in] ct the ABBE ciphertext.
     * @param[in] sk the ABBE secret key.
     */
    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk);


    /**
     * Frees the allocated content in the ABBE master key data structure of the CP-ABBE scheme.
     * @param[out] mk the (empty) ABBE master key.
     */
    void free_master_key(const master_key& mk);

    /**
     * Frees the allocated content in the ABBE public key data structure of the CP-ABBE scheme.
     * @param[out] pk the (empty) ABBE public key.
     */
    void free_public_key(public_key& pk);

    /**
     * Frees the allocated content in the ABBE secret key data structure of the CP-ABBE scheme.
     * @param[out] sk the (empty) ABBE secret key.
     */
    void free_secret_key(secret_key& sk);

    /**
     * Frees the allocated content in the ABBE ciphertext data structure of the CP-ABBE scheme.
     * @param[out] ct the (empty) ABBE ciphertext.
     */
    void free_ciphertext(ciphertext& ct);


    /**
     * Serializes the ABBE master key data structure of the CP-ABBE scheme to bytes.
     * @param[out] data the serialized ABBE master key is appended to this vector of bytes.
     * @param[in] mk the ABBE master key.
     */
    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk);

    /**
     * Deserializes the ABBE master key data structure of the CP-ABBE scheme from bytes.
     * @param[in] data the vector of bytes from which the ABBE master key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABBE master key start in "data".
     *      The offset is incremented by the size of the ABBE master key in bytes.
     * @returns the ABBE master key.
     */
    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr);

    /**
     * Serializes the ABBE public key data structure of the CP-ABBE scheme to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABBE public key is appended to this vector of bytes.
     * @param[in] pk the ABBE public key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk) {
        serialize_int<ATTR_TYPE>(data, pk.n);
        serialize_int<ATTR_TYPE>(data, pk.N1);
        serialize_g2_t_vector<ATTR_TYPE>(data, pk.gs_g2);
        serialize_g1_t_vector<ATTR_TYPE>(data, pk.gs_g1);
        serialize_g2_t_vector<ATTR_TYPE>(data, pk.hs_g2);
        serialize_g1_t_vector<ATTR_TYPE>(data, pk.hs_g1);
        serialize_g1_t(data, *pk.ny);
        serialize_g1_t(data, *pk.v0);
        serialize_g1_t(data, *pk.v1);
    }

    /**
     * Deserializes the ABBE public key data structure of the CP-ABBE scheme from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABBE public key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABBE public key start in "data".
     *      The offset is incremented by the size of the ABBE public key in bytes.
     * @returns the ABBE public key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr) {
        public_key pk;
        pk.n = deserialize_int<ATTR_TYPE>(data, offset_ptr);
        pk.N1 = deserialize_int<ATTR_TYPE>(data, offset_ptr);
        pk.gs_g2 = deserialize_g2_t_vector<ATTR_TYPE>(data, offset_ptr);
        pk.gs_g1 = deserialize_g1_t_vector<ATTR_TYPE>(data, offset_ptr);
        pk.hs_g2 = deserialize_g2_t_vector<ATTR_TYPE>(data, offset_ptr);
        pk.hs_g1 = deserialize_g1_t_vector<ATTR_TYPE>(data, offset_ptr);
        pk.ny = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*pk.ny);
        deserialize_g1_t(*pk.ny, data, offset_ptr);
        pk.v0 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*pk.v0);
        deserialize_g1_t(*pk.v0, data, offset_ptr);
        pk.v1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*pk.v1);
        deserialize_g1_t(*pk.v1, data, offset_ptr);
        return pk;
    }

    /**
     * Serializes the ABBE secret key data structure of the CP-ABBE scheme to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABBE secret key is appended to this vector of bytes.
     * @param[in] sk the ABBE secret key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_sk(std::vector<unsigned char>& data, const secret_key& sk) {
        serialize_int<ATTR_TYPE>(data, sk.id);
        serialize_int<ATTR_TYPE>(data, sk.n);
        serialize_g2_t_vector<ATTR_TYPE>(data, sk.gs_g2);
        serialize_g2_t(data, *sk.D1);
        serialize_g2_t(data, *sk.D2);
        serialize_g2_t(data, *sk.D3);
        serialize_g2_t_vector<ATTR_TYPE>(data, sk.D4s);
        serialize_g2_t_vector<ATTR_TYPE>(data, sk.D5s);
    }

    /**
     * Deserializes the ABBE secret key data structure of the CP-ABBE scheme from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABBE secret key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABBE secret key start in "data".
     *      The offset is incremented by the size of the ABBE secret key in bytes.
     * @returns the ABBE secret key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    secret_key deserialize_sk(const std::vector<unsigned char>& data, int *offset_ptr) {
        secret_key sk;
        sk.id = deserialize_int<ATTR_TYPE>(data, offset_ptr);
        sk.n = deserialize_int<ATTR_TYPE>(data, offset_ptr);
        sk.gs_g2 = deserialize_g2_t_vector<ATTR_TYPE>(data, offset_ptr);
        sk.D1 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*sk.D1);
        deserialize_g2_t(*sk.D1, data, offset_ptr);
        sk.D2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*sk.D2);
        deserialize_g2_t(*sk.D2, data, offset_ptr);
        sk.D3 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*sk.D3);
        deserialize_g2_t(*sk.D3, data, offset_ptr);
        sk.D4s = deserialize_g2_t_vector<ATTR_TYPE>(data, offset_ptr);
        sk.D5s = deserialize_g2_t_vector<ATTR_TYPE>(data, offset_ptr);
        return sk;
    }

    /**
     * Serializes the ABBE ciphertext data structure of the CP-ABBE scheme to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABBE ciphertext is appended to this vector of bytes.
     * @param[in] ct the ABBE ciphertext.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_ct(std::vector<unsigned char>& data, const ciphertext& ct) {
        const std::vector<ATTR_TYPE> S(ct.S.begin(), ct.S.end());
        serialize_int_vector<ATTR_TYPE, ATTR_TYPE>(data, S);
        const std::vector<ATTR_TYPE> J(ct.J.begin(), ct.J.end());
        serialize_int_vector<ATTR_TYPE, ATTR_TYPE>(data, J);
        serialize_gt_t(data, *ct.C0);
        serialize_g1_t(data, *ct.C1);
        serialize_g1_t(data, *ct.C2);
        serialize_g1_t(data, *ct.C3);
        serialize_g1_t(data, *ct.C4);
    }

    /**
     * Deserializes the ABBE ciphertext data structure of the CP-ABBE scheme from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABBE ciphertext is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABBE ciphertext start in "data".
     *      The offset is incremented by the size of the ABBE ciphertext in bytes.
     * @returns the ABBE ciphertext.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    ciphertext deserialize_ct(const std::vector<unsigned char>& data, int *offset_ptr) {
        ciphertext ct;
        const std::vector<ATTR_TYPE> S = deserialize_int_vector<ATTR_TYPE, ATTR_TYPE>(data, offset_ptr);
        ct.S = std::vector<int>(S.begin(), S.end());
        const std::vector<ATTR_TYPE> J = deserialize_int_vector<ATTR_TYPE, ATTR_TYPE>(data, offset_ptr);
        ct.J = std::vector<int>(J.begin(), J.end());
        ct.C0 = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ct.C0);
        deserialize_gt_t(*ct.C0, data, offset_ptr);
        ct.C1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*ct.C1);
        deserialize_g1_t(*ct.C1, data, offset_ptr);
        ct.C2 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*ct.C2);
        deserialize_g1_t(*ct.C2, data, offset_ptr);
        ct.C3 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*ct.C3);
        deserialize_g1_t(*ct.C3, data, offset_ptr);
        ct.C4 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*ct.C4);
        deserialize_g1_t(*ct.C4, data, offset_ptr);
        return ct;
    }
}

#endif //MASTER_CPABBE_S_H

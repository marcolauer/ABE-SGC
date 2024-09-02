#ifndef MASTER_KPABE_SWITCHER_H
#define MASTER_KPABE_SWITCHER_H

#include <variant>

#include "fibe.h"
#include "fibe_s.h"
#include "fibe_large.h"
#include "fibe_large_s.h"
#include "kpabe.h"
#include "kpabe_s.h"
#include "kpabe_large.h"
#include "kpabe_large_s.h"
#include "fame_kpabe.h"
#include "fabeo_kpabe.h"

namespace kpabe_switcher {
    enum abe_type {
        /**
         * The small universe construction of the Fuzzy-IBE scheme by Sahai and Waters
         * (<a href="https://eprint.iacr.org/2004/086.pdf">Link</a>). Converted for type-3 pairings.
         */
        FIBE,
        /**
         * The small universe construction of the Fuzzy-IBE scheme by Sahai and Waters
         * (<a href="https://eprint.iacr.org/2004/086.pdf">Link</a>). Converted for type-3 pairings. Implementation with
         * swapped groups G_1 and G_2.
         */
        FIBE_S,
        /**
         * The large universe construction of the Fuzzy-IBE scheme by Sahai and Waters
         * (<a href="https://eprint.iacr.org/2004/086.pdf">Link</a>). Converted for type-3 pairings.
         */
        FIBE_LARGE,
        /**
         * The small universe construction of the Fuzzy-IBE scheme by Sahai and Waters
         * (<a href="https://eprint.iacr.org/2004/086.pdf">Link</a>). Converted for type-3 pairings. Implementation with
         * swapped groups G_1 and G_2.
         */
        FIBE_LARGE_S,
        /**
         * The small universe construction of the KP-ABE scheme by Goyal et al.
         * (<a href="https://eprint.iacr.org/2006/309">Link</a>). Converted for type-3 pairings. With optimizations from
         * Bethencourt et al. (<a href="https://www.cs.utexas.edu/~bwaters/publications/papers/cp-abe.pdf">Link</a>).
         *
         */
        KPABE,
        /**
         * The small universe construction of the KP-ABE scheme by Goyal et al.
         * (<a href="https://eprint.iacr.org/2006/309">Link</a>). Converted for type-3 pairings. Implementation with
         * swapped groups G_1 and G_2. With optimizations from Bethencourt et al.
         * (<a href="https://www.cs.utexas.edu/~bwaters/publications/papers/cp-abe.pdf">Link</a>).
         */
        KPABE_S,
        /**
         * The large universe construction of the KP-ABE scheme by Goyal et al.
         * (<a href="https://eprint.iacr.org/2006/309">Link</a>). Converted for type-3 pairings. With optimizations from
         * Bethencourt et al. (<a href="https://www.cs.utexas.edu/~bwaters/publications/papers/cp-abe.pdf">Link</a>).
         */
        KPABE_LARGE,
        /**
         * The large universe construction of the KP-ABE scheme by Goyal et al.
         * (<a href="https://eprint.iacr.org/2006/309">Link</a>). Converted for type-3 pairings. Implementation with
         * swapped groups G_1 and G_2. With optimizations from Bethencourt et al.
         * (<a href="https://www.cs.utexas.edu/~bwaters/publications/papers/cp-abe.pdf">Link</a>).
         */
        KPABE_LARGE_S,
        /**
         * The FAME KP-ABE scheme by Agrawal and Chase (<a href="https://eprint.iacr.org/2017/807">Link</a>).
         */
        FAME_KPABE,
        /**
         * The FABEO KP-ABE scheme by Riepel and Wee (<a href="https://eprint.iacr.org/2022/1415">Link</a>).
         */
        FABEO_KPABE
    };

    using master_key = std::variant<fibe::master_key, fibe_s::master_key, fibe_large::master_key,
                                    fibe_large_s::master_key, kpabe::master_key, kpabe_s::master_key,
                                    kpabe_large::master_key, kpabe_large_s::master_key, fame_kpabe::master_key,
                                    fabeo_kpabe::master_key>;
    using public_key = std::variant<fibe::public_key, fibe_s::public_key, fibe_large::public_key,
                                    fibe_large_s::public_key, kpabe::public_key, kpabe_s::public_key,
                                    kpabe_large::public_key, kpabe_large_s::public_key, fame_kpabe::public_key,
                                    fabeo_kpabe::public_key>;
    using secret_key = std::variant<fibe::secret_key, fibe_s::secret_key, fibe_large::secret_key,
                                    fibe_large_s::secret_key, kpabe::secret_key, kpabe_s::secret_key,
                                    kpabe_large::secret_key, kpabe_large_s::secret_key, fame_kpabe::secret_key,
                                    fabeo_kpabe::secret_key>;
    using ciphertext = std::variant<fibe::ciphertext, fibe_s::ciphertext, fibe_large::ciphertext,
                                    fibe_large_s::ciphertext, kpabe::ciphertext, kpabe_s::ciphertext,
                                    kpabe_large::ciphertext, kpabe_large_s::ciphertext, fame_kpabe::ciphertext,
                                    fabeo_kpabe::ciphertext>;

    /**
     * Returns a string representation for the KP-ABE schemes in the abe_type enum.
     * @param[in] abe_type the chosen KP-ABE scheme.
     * @returns the string representation.
     */
    std::string type_to_string(abe_type abe_type);


    /**
     * Runs the setup algorithms of the KP-ABE schemes in the abe_type enum.
     * @param[out] mk the ABE master key.
     * @param[out] pk the ABE public key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void setup(master_key& mk, public_key& pk, bn_t order, abe_type abe_type);

    /**
     * Runs the key generation algorithms of the KP-ABE schemes in the abe_type enum.
     * @param[out] sk the ABE secret key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] policy the access structure for the ABE secret key.
     * @param[in] pk the ABE public key.
     * @param[in] mk the ABE master key.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void key_generation(secret_key& sk, bn_t order, TTree *policy, const public_key& pk, const master_key& mk,
                        abe_type abe_type);

    /**
     * Runs the encryption algorithms of the KP-ABE schemes in the abe_type enum.
     * @param[out] ct the ABE ciphertext.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] message the message to encrypt (an element of G_T).
     * @param[in] identity the identity for the ABE ciphertext.
     * @param[in] pk the ABE public key.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& identity, const public_key& pk,
                    abe_type abe_type);

    /**
     * Runs the decryption algorithms of the KP-ABE schemes in the abe_type enum.
     * @param[out] message the decrypted message (an element of G_T).
     * @param[in] order the order of the finite field Z_p.
     * @param[in] ct the ABE ciphertext.
     * @param[in] sk the ABE secret key.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk, abe_type abe_type);


    /**
     * Sets up the ABE master key data structures of the KP-ABE schemes in the abe_type enum.
     * @param abe_type the chosen KP-ABE scheme.
     * @returns the (empty) ABE master key.
     */
    master_key init_master_key(abe_type abe_type);

    /**
     * Sets up the ABE public key data structures of the KP-ABE schemes in the abe_type enum.
     * @param abe_type the chosen KP-ABE scheme.
     * @returns the (empty) ABE public key.
     */
    public_key init_public_key(abe_type abe_type);

    /**
     * Sets up the ABE secret key data structures of the KP-ABE schemes in the abe_type enum.
     * @param abe_type the chosen KP-ABE scheme.
     * @returns the (empty) ABE secret key.
     */
    secret_key init_secret_key(abe_type abe_type);

    /**
     * Sets up the ABE ciphertext data structures of the KP-ABE schemes in the abe_type enum.
     * @param abe_type the chosen KP-ABE scheme.
     * @returns the (empty) ABE ciphertext.
     */
    ciphertext init_ciphertext(abe_type abe_type);


    /**
     * Frees the allocated content in the ABE master key data structures of the KP-ABE schemes in the abe_type enum.
     * @param[out] mk the (empty) ABE master key.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void free_master_key(master_key& mk, abe_type abe_type);

    /**
     * Frees the allocated content in the ABE public key data structures of the KP-ABE schemes in the abe_type enum.
     * @param[out] pk the (empty) ABE public key.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void free_public_key(public_key& pk, abe_type abe_type);

    /**
     * Frees the allocated content in the ABE secret key data structures of the KP-ABE schemes in the abe_type enum.
     * @param[out] sk the (empty) ABE secret key.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void free_secret_key(secret_key& sk, abe_type abe_type);

    /**
     * Frees the allocated content in the ABE ciphertext data structures of the KP-ABE schemes in the abe_type enum.
     * @param[out] ct the (empty) ABE ciphertext.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void free_ciphertext(ciphertext& ct, abe_type abe_type);


    /**
     * Serializes the ABE master key data structures of the KP-ABE schemes in the abe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE master key is appended to this vector of bytes.
     * @param[in] mk the ABE master key.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::serialize_mk<ATTR_TYPE>(data, std::get<fibe::master_key>(mk));
            break;
            case FIBE_S:
                fibe_s::serialize_mk<ATTR_TYPE>(data, std::get<fibe_s::master_key>(mk));
            break;
            case FIBE_LARGE:
                fibe_large::serialize_mk(data, std::get<fibe_large::master_key>(mk));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::serialize_mk(data, std::get<fibe_large_s::master_key>(mk));
            break;
            case KPABE:
                kpabe::serialize_mk<ATTR_TYPE>(data, std::get<kpabe::master_key>(mk));
            break;
            case KPABE_S:
                kpabe_s::serialize_mk<ATTR_TYPE>(data, std::get<kpabe_s::master_key>(mk));
            break;
            case KPABE_LARGE:
                kpabe_large::serialize_mk(data, std::get<kpabe_large::master_key>(mk));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::serialize_mk(data, std::get<kpabe_large_s::master_key>(mk));
            break;
            case FAME_KPABE:
                fame_kpabe::serialize_mk(data, std::get<fame_kpabe::master_key>(mk));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::serialize_mk(data, std::get<fabeo_kpabe::master_key>(mk));
            break;
        }
    }

    /**
     * Deserializes the ABE master key data structures of the KP-ABE schemes in the abe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABE master key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE master key start in "data".
     *      The offset is incremented by the size of the ABE master key in bytes.
     * @param[in] abe_type the chosen KP-ABE scheme.
     * @returns the ABE master key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr, const abe_type abe_type) {
        master_key mk{};
        switch(abe_type) {
            case FIBE:
                return fibe::deserialize_mk<ATTR_TYPE>(data, offset_ptr);
            case FIBE_S:
                return fibe_s::deserialize_mk<ATTR_TYPE>(data, offset_ptr);
            case FIBE_LARGE:
                return fibe_large::deserialize_mk(data, offset_ptr);
            case FIBE_LARGE_S:
                return fibe_large_s::deserialize_mk(data, offset_ptr);
            case KPABE:
                return kpabe::deserialize_mk<ATTR_TYPE>(data, offset_ptr);
            case KPABE_S:
                return kpabe_s::deserialize_mk<ATTR_TYPE>(data, offset_ptr);
            case KPABE_LARGE:
                return kpabe_large::deserialize_mk(data, offset_ptr);
            case KPABE_LARGE_S:
                return kpabe_large_s::deserialize_mk(data, offset_ptr);
            case FAME_KPABE:
                return fame_kpabe::deserialize_mk(data, offset_ptr);
            case FABEO_KPABE:
                return fabeo_kpabe::deserialize_mk(data, offset_ptr);
        }
        return mk;
    }

    /**
     * Serializes the ABE public key data structures of the KP-ABE schemes in the abe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE public key is appended to this vector of bytes.
     * @param[in] pk the ABE public key.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::serialize_pk<ATTR_TYPE>(data, std::get<fibe::public_key>(pk));
            break;
            case FIBE_S:
                fibe_s::serialize_pk<ATTR_TYPE>(data, std::get<fibe_s::public_key>(pk));
            break;
            case FIBE_LARGE:
                fibe_large::serialize_pk<ATTR_TYPE>(data, std::get<fibe_large::public_key>(pk));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::serialize_pk<ATTR_TYPE>(data, std::get<fibe_large_s::public_key>(pk));
            break;
            case KPABE:
                kpabe::serialize_pk<ATTR_TYPE>(data, std::get<kpabe::public_key>(pk));
            break;
            case KPABE_S:
                kpabe_s::serialize_pk<ATTR_TYPE>(data, std::get<kpabe_s::public_key>(pk));
            break;
            case KPABE_LARGE:
                kpabe_large::serialize_pk<ATTR_TYPE>(data, std::get<kpabe_large::public_key>(pk));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::serialize_pk<ATTR_TYPE>(data, std::get<kpabe_large_s::public_key>(pk));
            break;
            case FAME_KPABE:
                fame_kpabe::serialize_pk(data, std::get<fame_kpabe::public_key>(pk));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::serialize_pk(data, std::get<fabeo_kpabe::public_key>(pk));
            break;
        }
    }

    /**
     * Deserializes the ABE public key data structures of the KP-ABE schemes in the abe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABE public key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE public key start in "data".
     *      The offset is incremented by the size of the ABE public key in bytes.
     * @param[in] abe_type the chosen KP-ABE scheme.
     * @returns the ABE public key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr, const abe_type abe_type) {
        public_key pk{};
        switch(abe_type) {
            case FIBE:
                return fibe::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
            case FIBE_S:
                return fibe_s::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
            case FIBE_LARGE:
                return fibe_large::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
            case FIBE_LARGE_S:
                return fibe_large_s::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
            case KPABE:
                return kpabe::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
            case KPABE_S:
                return kpabe_s::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
            case KPABE_LARGE:
                return kpabe_large::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
            case KPABE_LARGE_S:
                return kpabe_large_s::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
            case FAME_KPABE:
                return fame_kpabe::deserialize_pk(data, offset_ptr);
            case FABEO_KPABE:
                return fabeo_kpabe::deserialize_pk(data, offset_ptr);
        }
        return pk;
    }

    /**
     * Serializes the ABE secret key data structures of the KP-ABE schemes in the abe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE secret key is appended to this vector of bytes.
     * @param[in] sk the ABE secret key.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void serialize_sk(std::vector<unsigned char>& data, const secret_key& sk, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fibe::secret_key>(sk));
            break;
            case FIBE_S:
                fibe_s::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fibe_s::secret_key>(sk));
            break;
            case FIBE_LARGE:
                fibe_large::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fibe_large::secret_key>(sk));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fibe_large_s::secret_key>(sk));
            break;
            case KPABE:
                kpabe::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<kpabe::secret_key>(sk));
            break;
            case KPABE_S:
                kpabe_s::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<kpabe_s::secret_key>(sk));
            break;
            case KPABE_LARGE:
                kpabe_large::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<kpabe_large::secret_key>(sk));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<kpabe_large_s::secret_key>(sk));
            break;
            break;
            case FAME_KPABE:
                fame_kpabe::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fame_kpabe::secret_key>(sk));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fabeo_kpabe::secret_key>(sk));
            break;
        }
    }

    /**
     * Deserializes the ABE secret key data structures of the KP-ABE schemes in the abe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABE secret key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE secret key start in "data".
     *      The offset is incremented by the size of the ABE secret key in bytes.
     * @param[in] abe_type the chosen KP-ABE scheme.
     * @returns the ABE secret key.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    secret_key deserialize_sk(const std::vector<unsigned char>& data, int *offset_ptr, const abe_type abe_type) {
        secret_key sk{};
        switch(abe_type) {
            case FIBE:
                return fibe::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FIBE_S:
                return fibe_s::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FIBE_LARGE:
                return fibe_large::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FIBE_LARGE_S:
                return fibe_large_s::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case KPABE:
                return kpabe::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case KPABE_S:
                return kpabe_s::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case KPABE_LARGE:
                return kpabe_large::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case KPABE_LARGE_S:
                return kpabe_large_s::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FAME_KPABE:
                return fame_kpabe::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FABEO_KPABE:
                return fabeo_kpabe::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        }
        return sk;
    }

    /**
     * Serializes the ABE ciphertext data structures of the KP-ABE schemes in the abe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE ciphertext is appended to this vector of bytes.
     * @param[in] ct the ABE ciphertext.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void serialize_ct(std::vector<unsigned char>& data, const ciphertext& ct, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fibe::ciphertext>(ct));
            break;
            case FIBE_S:
                fibe_s::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fibe_s::ciphertext>(ct));
            break;
            case FIBE_LARGE:
                fibe_large::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fibe_large::ciphertext>(ct));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fibe_large_s::ciphertext>(ct));
            break;
            case KPABE:
                kpabe::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<kpabe::ciphertext>(ct));
            break;
            case KPABE_S:
                kpabe_s::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<kpabe_s::ciphertext>(ct));
            break;
            case KPABE_LARGE:
                kpabe_large::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<kpabe_large::ciphertext>(ct));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<kpabe_large_s::ciphertext>(ct));
            break;
            break;
            case FAME_KPABE:
                fame_kpabe::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fame_kpabe::ciphertext>(ct));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fabeo_kpabe::ciphertext>(ct));
            break;
        }
    }

    /**
     * Deserializes the ABE ciphertext data structures of the KP-ABE schemes in the abe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABE ciphertext is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE ciphertext start in "data".
     *      The offset is incremented by the size of the ABE ciphertext in bytes.
     * @param[in] abe_type the chosen KP-ABE scheme.
     * @returns the ABE ciphertext.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    ciphertext deserialize_ct(const std::vector<unsigned char>& data, int *offset_ptr, const abe_type abe_type) {
        ciphertext ct{};
        switch(abe_type) {
            case FIBE:
                return fibe::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FIBE_S:
                return fibe_s::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FIBE_LARGE:
                return fibe_large::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FIBE_LARGE_S:
                return fibe_large_s::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case KPABE:
                return kpabe::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case KPABE_S:
                return kpabe_s::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case KPABE_LARGE:
                return kpabe_large::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case KPABE_LARGE_S:
                return kpabe_large_s::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FAME_KPABE:
                return fame_kpabe::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FABEO_KPABE:
                return fabeo_kpabe::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        }
        return ct;
    }


    /**
     * Tests the functionality of the KP-ABE schemes in the abe_type enum and prints the result.
     * @param[in] publisher_id the identity used in the encryption.
     * @param[in] recipient_policy the access structure used in the decryption.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void test(const std::vector<int>& publisher_id, TTree *recipient_policy, abe_type abe_type);

    /**
     * Measures and prints the average runtimes and standard deviation for the KP-ABE algorithms (setup, key_generation,
     * encryption, decryption) in the abe_type enum.
     * @param[in] publisher_id the identity used in the encryption.
     * @param[in] recipient_policy the access structure used in the decryption.
     * @param[in] precision how many digits to print after the decimal point of the runtimes.
     * @param[in] repetitions how many repetitions to perform for each measurement.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    void measure_runtimes(const std::vector<int>& publisher_id, TTree *recipient_policy, int precision, int repetitions, abe_type abe_type);

    /**
     * Measures and prints the sizes of the KP-ABE data structures (master key, public key, secret key, ciphertext)
     * in the abe_type enum.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[in] publisher_id the identity used in the encryption.
     * @param[in] recipient_policy the access structure used in the decryption.
     * @param[in] abe_type the chosen KP-ABE scheme.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void measure_byte_lengths(const std::vector<int>& publisher_id, TTree *recipient_policy, const abe_type abe_type) {
        // Setup
        bn_t order;
        bn_util_null_init(order);
        pc_get_ord(order);
        master_key mk = init_master_key(abe_type);
        public_key pk = init_public_key(abe_type);
        secret_key sk = init_secret_key(abe_type);
        ciphertext ct = init_ciphertext(abe_type);
        gt_t sent_message;
        gt_util_null_init(sent_message);

        // Test
        gt_rand(sent_message);
        setup(mk, pk, order, abe_type);
        key_generation(sk, order, recipient_policy, pk, mk, abe_type);
        encryption(ct, order, sent_message, publisher_id, pk, abe_type);

        std::vector<unsigned char> data;
        const std::string abe_type_string = type_to_string(abe_type);
        serialize_mk<ATTR_TYPE>(data, mk, abe_type);
        std::cout << abe_type_string << " Master Key Size: " << data.size() << " Bytes" << std::endl;
        data.clear();
        serialize_pk<ATTR_TYPE>(data, pk, abe_type);
        std::cout << abe_type_string << " Public Key Size: " << data.size() << " Bytes" << std::endl;
        data.clear();
        serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, sk, abe_type);
        std::cout << abe_type_string << " Secret Key Size: " << data.size() << " Bytes" << std::endl;
        data.clear();
        serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, ct, abe_type);
        std::cout << abe_type_string << " Ciphertext Size: " << data.size() << " Bytes" << std::endl;

        // Cleanup
        free_master_key(mk, abe_type);
        free_public_key(pk, abe_type);
        free_secret_key(sk, abe_type);
        free_ciphertext(ct, abe_type);
        gt_free(sent_message);
        bn_free(order);
    }
}

#endif //MASTER_KPABE_SWITCHER_H

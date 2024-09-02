#ifndef MASTER_KPABBE_SWITCHER_H
#define MASTER_KPABBE_SWITCHER_H

#include <variant>
#include "kpabbe.h"
#include "kpabbe_s.h"


namespace kpabbe_switcher {
    enum abbe_type {
        /**
         * The KP-ABBE scheme by Phuong et al. (<a href="http://dx.doi.org/10.1007/978-3-319-24177-7_13">Link</a>).
         * Converted for type-3 pairings.
         */
        KPABBE,
        /**
         * The KP-ABBE scheme by Phuong et al. (<a href="http://dx.doi.org/10.1007/978-3-319-24177-7_13">Link</a>).
         * Converted for type-3 pairings. Implementation with swapped groups G_1 and G_2.
         */
        KPABBE_S
    };

    using master_key = std::variant<kpabbe::master_key, kpabbe_s::master_key>;
    using public_key = std::variant<kpabbe::public_key, kpabbe_s::public_key>;
    using secret_key = std::variant<kpabbe::secret_key, kpabbe_s::secret_key>;
    using ciphertext = std::variant<kpabbe::ciphertext, kpabbe_s::ciphertext>;

    /**
     * Returns a string representation for the KP-ABBE schemes in the abbe_type enum.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     * @returns the string representation.
     */
    std::string type_to_string(abbe_type abbe_type);


    /**
     * Runs the setup algorithms of the KP-ABBE schemes in the abbe_type enum.
     * @param[out] mk the ABBE master key.
     * @param[out] pk the ABBE public key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void setup(master_key& mk, public_key& pk, bn_t order, abbe_type abbe_type);

    /**
     * Runs the key generation algorithms of the KP-ABBE schemes in the abbe_type enum.
     * @param[out] sk the ABBE secret key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] id the id of the owner of the secret key.
     * @param[in] J the wildcard attributes of the access structure for the ABBE secret key.
     * @param[in] V the positive attributes of the access structure for the ABBE secret key.
     * @param[in] Z the negative attributes of the access structure for the ABBE secret key.
     * @param[in] pk the ABBE public key.
     * @param[in] mk the ABBE master key.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void key_generation(secret_key& sk, bn_t order, int id, const std::vector<int>& J, const std::vector<int>& V,
                        const std::vector<int>& Z, const public_key& pk, const master_key& mk, abbe_type abbe_type);

    /**
     * Runs the encryption algorithms of the KP-ABBE schemes in the abbe_type enum.
     * @param[out] ct the ABBE ciphertext.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] message the message to encrypt (an element of G_T).
     * @param[in] S the set of user ids that are allowed to decrypt.
     * @param[in] V the positive attributes of the identity for the ABBE ciphertext.
     * @param[in] Z the negative attributes of the identity for the ABBE ciphertext.
     * @param[in] pk the ABBE public key.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& S, const std::vector<int>& V,
                    const std::vector<int>& Z, const public_key& pk, abbe_type abbe_type);

    /**
     * Runs the decryption algorithms of the KP-ABBE schemes in the abbe_type enum.
     * @param[out] message the decrypted message (an element of G_T).
     * @param[in] order the order of the finite field Z_p.
     * @param[in] ct the ABBE ciphertext.
     * @param[in] sk the ABBE secret key.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk, abbe_type abbe_type);


    /**
     * Sets up the ABBE master key data structures of the KP-ABBE schemes in the abbe_type enum.
     * @param abbe_type the chosen KP-ABBE scheme.
     * @returns the (empty) ABBE master key.
     */
    master_key init_master_key(abbe_type abbe_type);

    /**
     * Sets up the ABBE public key data structures of the KP-ABBE schemes in the abbe_type enum.
     * @param abbe_type the chosen KP-ABBE scheme.
     * @returns the (empty) ABBE public key.
     */
    public_key init_public_key(abbe_type abbe_type);

    /**
     * Sets up the ABBE secret key data structures of the KP-ABBE schemes in the abbe_type enum.
     * @param abbe_type the chosen KP-ABBE scheme.
     * @returns the (empty) ABBE secret key.
     */
    secret_key init_secret_key(abbe_type abbe_type);

    /**
     * Sets up the ABBE ciphertext data structures of the KP-ABBE schemes in the abbe_type enum.
     * @param abbe_type the chosen KP-ABBE scheme.
     * @returns the (empty) ABBE ciphertext.
     */
    ciphertext init_ciphertext(abbe_type abbe_type);


    /**
     * Frees the allocated content in the ABBE master key data structures of the KP-ABBE schemes in the abbe_type enum.
     * @param[out] mk the (empty) ABBE master key.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void free_master_key(master_key& mk, abbe_type abbe_type);

    /**
     * Frees the allocated content in the ABBE public key data structures of the KP-ABBE schemes in the abbe_type enum.
     * @param[out] pk the (empty) ABBE public key.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void free_public_key(public_key& pk, abbe_type abbe_type);

    /**
     * Frees the allocated content in the ABBE secret key data structures of the KP-ABBE schemes in the abbe_type enum.
     * @param[out] sk the (empty) ABBE secret key.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void free_secret_key(secret_key& sk, abbe_type abbe_type);

    /**
     * Frees the allocated content in the ABBE ciphertext data structures of the KP-ABBE schemes in the abbe_type enum.
     * @param[out] ct the (empty) ABBE ciphertext.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void free_ciphertext(ciphertext& ct, abbe_type abbe_type);

    /**
     * Serializes the ABBE master key data structures of the KP-ABBE schemes in the abbe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABBE master key is appended to this vector of bytes.
     * @param[in] mk the ABBE master key.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case KPABBE:
                kpabbe::serialize_mk<ATTR_TYPE>(data, std::get<kpabbe::master_key>(mk));
            break;
            case KPABBE_S:
                kpabbe_s::serialize_mk<ATTR_TYPE>(data, std::get<kpabbe_s::master_key>(mk));
            break;
        }
    }

    /**
     * Deserializes the ABBE master key data structures of the KP-ABBE schemes in the abbe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABBE master key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABBE master key start in "data".
     *      The offset is incremented by the size of the ABBE master key in bytes.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     * @returns the ABBE master key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr, const abbe_type abbe_type) {
        master_key mk{};
        switch(abbe_type) {
            case KPABBE:
                return kpabbe::deserialize_mk<ATTR_TYPE>(data, offset_ptr);
            case KPABBE_S:
                return kpabbe_s::deserialize_mk<ATTR_TYPE>(data, offset_ptr);
        }
        return mk;
    }

    /**
     * Serializes the ABBE public key data structures of the KP-ABBE schemes in the abbe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABBE public key is appended to this vector of bytes.
     * @param[in] pk the ABBE public key.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case KPABBE:
                kpabbe::serialize_pk<ATTR_TYPE>(data, std::get<kpabbe::public_key>(pk));
            break;
            case KPABBE_S:
                kpabbe_s::serialize_pk<ATTR_TYPE>(data, std::get<kpabbe_s::public_key>(pk));
            break;
        }
    }

    /**
     * Deserializes the ABBE public key data structures of the KP-ABBE schemes in the abbe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABBE public key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABBE public key start in "data".
     *      The offset is incremented by the size of the ABBE public key in bytes.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     * @returns the ABBE public key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr, const abbe_type abbe_type) {
        public_key pk{};
        switch(abbe_type) {
            case KPABBE:
                return kpabbe::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
            case KPABBE_S:
                return kpabbe_s::deserialize_pk<ATTR_TYPE>(data, offset_ptr);
        }
        return pk;
    }

    /**
     * Serializes the ABBE secret key data structures of the KP-ABBE schemes in the abbe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABBE secret key is appended to this vector of bytes.
     * @param[in] sk the ABBE secret key.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_sk(std::vector<unsigned char>& data, const secret_key& sk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case KPABBE:
                kpabbe::serialize_sk<ATTR_TYPE>(data, std::get<kpabbe::secret_key>(sk));
            break;
            case KPABBE_S:
                kpabbe_s::serialize_sk<ATTR_TYPE>(data, std::get<kpabbe_s::secret_key>(sk));
            break;
        }
    }

    /**
     * Deserializes the ABBE secret key data structures of the KP-ABBE schemes in the abbe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABBE secret key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABBE secret key start in "data".
     *      The offset is incremented by the size of the ABBE secret key in bytes.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     * @returns the ABBE secret key.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    secret_key deserialize_sk(const std::vector<unsigned char>& data, int *offset_ptr, const abbe_type abbe_type) {
        secret_key sk{};
        switch(abbe_type) {
            case KPABBE:
                return kpabbe::deserialize_sk<ATTR_TYPE>(data, offset_ptr);
            case KPABBE_S:
                return kpabbe_s::deserialize_sk<ATTR_TYPE>(data, offset_ptr);
        }
        return sk;
    }

    /**
     * Serializes the ABBE ciphertext data structures of the KP-ABBE schemes in the abbe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABBE ciphertext is appended to this vector of bytes.
     * @param[in] ct the ABBE ciphertext.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void serialize_ct(std::vector<unsigned char>& data, const ciphertext& ct, const abbe_type abbe_type) {
        switch(abbe_type) {
            case KPABBE:
                kpabbe::serialize_ct<ATTR_TYPE>(data, std::get<kpabbe::ciphertext>(ct));
            break;
            case KPABBE_S:
                kpabbe_s::serialize_ct<ATTR_TYPE>(data, std::get<kpabbe_s::ciphertext>(ct));
            break;
        }
    }

    /**
     * Deserializes the ABBE ciphertext data structures of the KP-ABBE schemes in the abbe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABBE ciphertext is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABBE ciphertext start in "data".
     *      The offset is incremented by the size of the ABBE ciphertext in bytes.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     * @returns the ABBE ciphertext.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    ciphertext deserialize_ct(const std::vector<unsigned char>& data, int *offset_ptr, const abbe_type abbe_type) {
        ciphertext ct{};
        switch(abbe_type) {
            case KPABBE:
                return kpabbe::deserialize_ct<ATTR_TYPE>(data, offset_ptr);
            case KPABBE_S:
                return kpabbe_s::deserialize_ct<ATTR_TYPE>(data, offset_ptr);
        }
        return ct;
    }


    /**
     * Tests the functionality of the KP-ABBE schemes in the abbe_type enum and prints the result.
     * @param[in] id the user id used in the decryption
     * @param[in] S the set of user ids used in the encryption (only these are allowed to decrypt).
     * @param[in] V the positive attributes of the identity used in the encryption.
     * @param[in] Z the negative attributes of the identity used in the encryption.
     * @param[in] J the wildcard attributes of the access structure used in the decryption.
     * @param[in] Vprime the positive attributes of the access structure used in the decryption.
     * @param[in] Zprime the negative attributes of the access structure used in the decryption.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void test(int id, const std::vector<int>& S, const std::vector<int>& V, const std::vector<int>& Z,
              const std::vector<int>& J, const std::vector<int>& Vprime, const std::vector<int>& Zprime,
              abbe_type abbe_type);

    /**
     * Measures and prints the average runtimes and standard deviation for the KP-ABBE algorithms (setup, key_generation,
     * encryption, decryption) in the abbe_type enum.
     * @param[in] id the user id used in the decryption.
     * @param[in] S the set of user ids used in the encryption (only these are allowed to decrypt).
     * @param[in] V the positive attributes of the identity used in the encryption.
     * @param[in] Z the negative attributes of the identity used in the encryption.
     * @param[in] J the wildcard attributes of the access structure used in the decryption.
     * @param[in] Vprime the positive attributes of the access structure used in the decryption.
     * @param[in] Zprime the negative attributes of the access structure used in the decryption.
     * @param[in] precision how many digits to print after the decimal point of the runtimes.
     * @param[in] repetitions how many repetitions to perform for each measurement.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    void measure_runtimes(int id, const std::vector<int>& S, const std::vector<int>& V, const std::vector<int>& Z,
                          const std::vector<int>& J, const std::vector<int>& Vprime, const std::vector<int>& Zprime,
                          int precision, int repetitions, abbe_type abbe_type);

    /**
     * Measures and prints the sizes of the KP-ABBE data structures (master key, public key, secret key, ciphertext)
     * in the abbe_type enum.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @param[in] id the user id used in the decryption.
     * @param[in] S the set of user ids used in the encryption (only these are allowed to decrypt).
     * @param[in] V the positive attributes of the identity used in the encryption.
     * @param[in] Z the negative attributes of the identity used in the encryption.
     * @param[in] J the wildcard attributes of the access structure used in the decryption.
     * @param[in] Vprime the positive attributes of the access structure used in the decryption.
     * @param[in] Zprime the negative attributes of the access structure used in the decryption.
     * @param[in] abbe_type the chosen KP-ABBE scheme.
     */
    template<typename ATTR_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true>
    void measure_byte_lengths(const int id, const std::vector<int>& S, const std::vector<int>& V,
                              const std::vector<int>& Z, const std::vector<int>& J, const std::vector<int>& Vprime,
                              const std::vector<int>& Zprime, const abbe_type abbe_type) {
        // Setup
        bn_t order;
        bn_util_null_init(order);
        pc_get_ord(order);
        master_key mk = init_master_key(abbe_type);
        public_key pk = init_public_key(abbe_type);
        secret_key sk = init_secret_key(abbe_type);
        ciphertext ct = init_ciphertext(abbe_type);
        gt_t sent_message;
        gt_util_null_init(sent_message);

        // Test
        gt_rand(sent_message);
        setup(mk, pk, order, abbe_type);
        key_generation(sk, order, id, J, Vprime, Zprime, pk, mk, abbe_type);
        encryption(ct, order, sent_message, S, V, Z, pk, abbe_type);

        std::vector<unsigned char> data;
        const std::string abbe_type_string = type_to_string(abbe_type);
        serialize_mk<ATTR_TYPE>(data, mk, abbe_type);
        std::cout << abbe_type_string << " Master Key Size: " << data.size() << " Bytes" << std::endl;
        data.clear();
        serialize_pk<ATTR_TYPE>(data, pk, abbe_type);
        std::cout << abbe_type_string << " Public Key Size: " << data.size() << " Bytes" << std::endl;
        data.clear();
        serialize_sk<ATTR_TYPE>(data, sk, abbe_type);
        std::cout << abbe_type_string << " Secret Key Size: " << data.size() << " Bytes" << std::endl;
        data.clear();
        serialize_ct<ATTR_TYPE>(data, ct, abbe_type);
        std::cout << abbe_type_string << " Ciphertext Size: " << data.size() << " Bytes" << std::endl;

        // Cleanup
        free_master_key(mk, abbe_type);
        free_public_key(pk, abbe_type);
        free_secret_key(sk, abbe_type);
        free_ciphertext(ct, abbe_type);
        gt_free(sent_message);
        bn_free(order);
    }
}

#endif //MASTER_KPABBE_SWITCHER_H

#ifndef MASTER_CPABE_SWITCHER_H
#define MASTER_CPABE_SWITCHER_H

#include <variant>
#include "cpabe.h"
#include "cpabe_s.h"
#include "fame_cpabe.h"
#include "fabeo_cpabe.h"
#include "../AOTree.h"


namespace cpabe_switcher {
    enum abe_type {
        /**
         * The CP-ABE scheme by Bethencourt et al.
         * (<a href="https://www.cs.utexas.edu/~bwaters/publications/papers/cp-abe.pdf">Link</a>). Converted for type-3
         * pairings. With optimizations from the same paper.
         */
        CPABE,
        /**
         * The CP-ABE scheme by Bethencourt et al.
         * (<a href="https://www.cs.utexas.edu/~bwaters/publications/papers/cp-abe.pdf">Link</a>). Converted for type-3
         * pairings. Implementation with swapped groups G_1 and G_2. With optimizations from the same paper.
         */
        CPABE_S,
        /**
         * The FAME CP-ABE scheme by Agrawal and Chase (<a href="https://eprint.iacr.org/2017/807">Link</a>).
         */
        FAME_CPABE,
        /**
         * The FABEO CP-ABE scheme by Riepel and Wee (<a href="https://eprint.iacr.org/2022/1415">Link</a>).
         */
        FABEO_CPABE
    };

    using master_key = std::variant<cpabe::master_key, cpabe_s::master_key, fame_cpabe::master_key, fabeo_cpabe::master_key>;
    using public_key = std::variant<cpabe::public_key, cpabe_s::public_key, fame_cpabe::public_key, fabeo_cpabe::public_key>;
    using secret_key = std::variant<cpabe::secret_key, cpabe_s::secret_key, fame_cpabe::secret_key, fabeo_cpabe::secret_key>;
    using ciphertext = std::variant<cpabe::ciphertext, cpabe_s::ciphertext, fame_cpabe::ciphertext, fabeo_cpabe::ciphertext>;

    /**
     * Returns a string representation for the CP-ABE schemes in the abe_type enum.
     * @param[in] abe_type the chosen CP-ABE scheme.
     * @returns the string representation.
     */
    std::string type_to_string(abe_type abe_type);


    /**
     * Runs the setup algorithms of the CP-ABE schemes in the abe_type enum.
     * @param[out] mk the ABE master key.
     * @param[out] pk the ABE public key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void setup(master_key& mk, public_key& pk, bn_t order, abe_type abe_type);

    /**
     * Runs the key generation algorithms of the CP-ABE schemes in the abe_type enum.
     * @param[out] sk the ABE secret key.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] identity the identity for the ABE secret key.
     * @param[in] pk the ABE public key.
     * @param[in] mk the ABE master key.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void key_generation(secret_key& sk, bn_t order, const std::vector<int>& identity, const public_key& pk,
                        const master_key& mk, abe_type abe_type);

    /**
     * Runs the encryption algorithms of the CP-ABE schemes in the abe_type enum.
     * @param[out] ct the ABE ciphertext.
     * @param[in] order the order of the finite field Z_p.
     * @param[in] message the message to encrypt (an element of G_T).
     * @param[in] policy the access structure for the ABE ciphertext.
     * @param[in] pk the ABE public key.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void encryption(ciphertext& ct, bn_t order, gt_t message, TTree *policy, const public_key& pk, abe_type abe_type);

    /**
     * Runs the decryption algorithms of the CP-ABE schemes in the abe_type enum.
     * @param[out] message the decrypted message (an element of G_T).
     * @param[in] order the order of the finite field Z_p.
     * @param[in] ct the ABE ciphertext.
     * @param[in] sk the ABE secret key.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk, abe_type abe_type);


    /**
     * Sets up the ABE master key data structures of the CP-ABE schemes in the abe_type enum.
     * @param abe_type the chosen CP-ABE scheme.
     * @returns the (empty) ABE master key.
     */
    master_key init_master_key(abe_type abe_type);

    /**
     * Sets up the ABE public key data structures of the CP-ABE schemes in the abe_type enum.
     * @param abe_type the chosen CP-ABE scheme.
     * @returns the (empty) ABE public key.
     */
    public_key init_public_key(abe_type abe_type);

    /**
     * Sets up the ABE secret key data structures of the CP-ABE schemes in the abe_type enum.
     * @param abe_type the chosen CP-ABE scheme.
     * @returns the (empty) ABE secret key.
     */
    secret_key init_secret_key(abe_type abe_type);

    /**
     * Sets up the ABE ciphertext data structures of the CP-ABE schemes in the abe_type enum.
     * @param abe_type the chosen CP-ABE scheme.
     * @returns the (empty) ABE ciphertext.
     */
    ciphertext init_ciphertext(abe_type abe_type);


    /**
     * Frees the allocated content in the ABE master key data structures of the CP-ABE schemes in the abe_type enum.
     * @param[out] mk the (empty) ABE master key.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void free_master_key(master_key& mk, abe_type abe_type);

    /**
     * Frees the allocated content in the ABE public key data structures of the CP-ABE schemes in the abe_type enum.
     * @param[out] pk the (empty) ABE public key.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void free_public_key(public_key& pk, abe_type abe_type);

    /**
     * Frees the allocated content in the ABE secret key data structures of the CP-ABE schemes in the abe_type enum.
     * @param[out] sk the (empty) ABE secret key.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void free_secret_key(secret_key& sk, abe_type abe_type);

    /**
     * Frees the allocated content in the ABE ciphertext data structures of the CP-ABE schemes in the abe_type enum.
     * @param[out] ct the (empty) ABE ciphertext.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void free_ciphertext(ciphertext& ct, abe_type abe_type);


    /**
     * Serializes the ABE master key data structures of the CP-ABE schemes in the abe_type enum to bytes.
     * @param[out] data the serialized ABE master key is appended to this vector of bytes.
     * @param[in] mk the ABE master key.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk, abe_type abe_type);

    /**
     * Deserializes the ABE master key data structures of the CP-ABE schemes in the abe_type enum from bytes.
     * @param[in] data the vector of bytes from which the ABE master key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE master key start in "data".
     *      The offset is incremented by the size of the ABE master key in bytes.
     * @param[in] abe_type the chosen CP-ABE scheme.
     * @returns the ABE master key.
     */
    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr, abe_type abe_type);

    /**
     * Serializes the ABE public key data structures of the CP-ABE schemes in the abe_type enum to bytes.
     * @param[out] data the serialized ABE public key is appended to this vector of bytes.
     * @param[in] pk the ABE public key.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk, abe_type abe_type);

    /**
     * Deserializes the ABE public key data structures of the CP-ABE schemes in the abe_type enum from bytes.
     * @param[in] data the vector of bytes from which the ABE public key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE public key start in "data".
     *      The offset is incremented by the size of the ABE public key in bytes.
     * @param[in] abe_type the chosen CP-ABE scheme.
     * @returns the ABE public key.
     */
    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr, abe_type abe_type);

    /**
     * Serializes the ABE secret key data structures of the CP-ABE schemes in the abe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE secret key is appended to this vector of bytes.
     * @param[in] sk the ABE secret key.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void serialize_sk(std::vector<unsigned char>& data, const secret_key& sk, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<cpabe::secret_key>(sk));
            break;
            case CPABE_S:
                cpabe_s::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<cpabe_s::secret_key>(sk));
            break;
            case FAME_CPABE:
                fame_cpabe::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fame_cpabe::secret_key>(sk));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::serialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fabeo_cpabe::secret_key>(sk));
            break;
        }
    }

    /**
     * Deserializes the ABE secret key data structures of the CP-ABE schemes in the abe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABE secret key is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE secret key start in "data".
     *      The offset is incremented by the size of the ABE secret key in bytes.
     * @param[in] abe_type the chosen CP-ABE scheme.
     * @returns the ABE secret key.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    secret_key deserialize_sk(const std::vector<unsigned char>& data, int *offset_ptr, const abe_type abe_type) {
        secret_key sk{};
        switch(abe_type) {
            case CPABE:
                return cpabe::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case CPABE_S:
                return cpabe_s::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FAME_CPABE:
                return fame_cpabe::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FABEO_CPABE:
                return fabeo_cpabe::deserialize_sk<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        }
        return sk;
    }

    /**
     * Serializes the ABE ciphertext data structures of the CP-ABE schemes in the abe_type enum to bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[out] data the serialized ABE ciphertext is appended to this vector of bytes.
     * @param[in] ct the ABE ciphertext.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void serialize_ct(std::vector<unsigned char>& data, const ciphertext& ct, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<cpabe::ciphertext>(ct));
            break;
            case CPABE_S:
                cpabe_s::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<cpabe_s::ciphertext>(ct));
            break;
            case FAME_CPABE:
                fame_cpabe::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fame_cpabe::ciphertext>(ct));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::serialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, std::get<fabeo_cpabe::ciphertext>(ct));
            break;
        }
    }

    /**
     * Deserializes the ABE ciphertext data structures of the CP-ABE schemes in the abe_type enum from bytes.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[in] data the vector of bytes from which the ABE ciphertext is deserialized.
     * @param[inout] offset_ptr a pointer to the offset at which the bytes for the ABE ciphertext start in "data".
     *      The offset is incremented by the size of the ABE ciphertext in bytes.
     * @param[in] abe_type the chosen CP-ABE scheme.
     * @returns the ABE ciphertext.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    ciphertext deserialize_ct(const std::vector<unsigned char>& data, int *offset_ptr, const abe_type abe_type) {
        ciphertext ct{};
        switch(abe_type) {
            case CPABE:
                return cpabe::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case CPABE_S:
                return cpabe_s::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FAME_CPABE:
                return fame_cpabe::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
            case FABEO_CPABE:
                return fabeo_cpabe::deserialize_ct<ATTR_TYPE, IDENTITY_SIZE_TYPE>(data, offset_ptr);
        }
        return ct;
    }


    /**
     * Tests the functionality of the CP-ABE schemes in the abe_type enum and prints the result.
     * @param[in] publisher_policy the access structure used in the encryption.
     * @param[in] recipient_id the identity used in the decryption.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void test(TTree *publisher_policy, const std::vector<int>& recipient_id, abe_type abe_type);

    /**
     * Measures and prints the average runtimes and standard deviation for the CP-ABE algorithms (setup, key_generation,
     * encryption, decryption) in the abe_type enum.
     * @param[in] publisher_policy the access structure used in the encryption.
     * @param[in] recipient_id the identity used in the decryption.
     * @param[in] precision how many digits to print after the decimal point of the runtimes.
     * @param[in] repetitions how many repetitions to perform for each measurement.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    void measure_runtimes(TTree *publisher_policy, const std::vector<int>& recipient_id, int precision, int repetitions, abe_type abe_type);

    /**
     * Measures and prints the sizes of the CP-ABE data structures (master key, public key, secret key, ciphertext)
     * in the abe_type enum.
     * @tparam ATTR_TYPE the data type used for the attributes (e.g. uint8_t, uint16_t, ...).
     * @tparam IDENTITY_SIZE_TYPE the data type used for serializing the length of the identities / access structures
     *      (e.g. uint8_t, uint16_t, ...).
     * @param[in] publisher_policy the access structure used in the encryption.
     * @param[in] recipient_id the identity used in the decryption.
     * @param[in] abe_type the chosen CP-ABE scheme.
     */
    template<typename ATTR_TYPE, typename IDENTITY_SIZE_TYPE, std::enable_if_t<std::is_integral_v<ATTR_TYPE>, bool> = true,
    std::enable_if_t<std::is_integral_v<IDENTITY_SIZE_TYPE>, bool> = true>
    void measure_byte_lengths(TTree *publisher_policy, const std::vector<int>& recipient_id, const abe_type abe_type) {
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
        key_generation(sk, order, recipient_id, pk, mk, abe_type);
        encryption(ct, order, sent_message, publisher_policy, pk, abe_type);

        std::vector<unsigned char> data;
        const std::string abe_type_string = type_to_string(abe_type);
        serialize_mk(data, mk, abe_type);
        std::cout << abe_type_string << " Master Key Size: " << data.size() << " Bytes" << std::endl;
        data.clear();
        serialize_pk(data, pk, abe_type);
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

#endif //MASTER_CPABE_SWITCHER_H

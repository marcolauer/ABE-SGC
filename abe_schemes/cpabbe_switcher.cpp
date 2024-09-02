#include "cpabbe_switcher.h"
#include <chrono>
#include <iomanip>
#include "../config.h"

namespace cpabbe_switcher {
    using TIMER_PRECISION = std::chrono::microseconds;
    // Maximum number of users/attributes
    constexpr int n = MASTER_UNIVERSE_SIZE;
    // Maximum number of attributes
    constexpr int N = MASTER_UNIVERSE_SIZE;
    // Maximum number of wildcards in an access structure
    constexpr int N1 = 0;

    std::string type_to_string(const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                return "CPABBE";
            case CPABBE_S:
                return "CPABBE S";
        }
        return "";
    }

    void setup(master_key& mk, public_key& pk, bn_t order, const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                cpabbe::setup(std::get<cpabbe::master_key>(mk), std::get<cpabbe::public_key>(pk),
                              order, n, N, N1);
            break;
            case CPABBE_S:
                cpabbe_s::setup(std::get<cpabbe_s::master_key>(mk), std::get<cpabbe_s::public_key>(pk),
                                order, n, N, N1);
            break;
        }
    }

    void key_generation(secret_key& sk, bn_t order, const int id, const std::vector<int>& V, const std::vector<int>& Z,
                        const public_key& pk, const master_key& mk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                cpabbe::key_generation(std::get<cpabbe::secret_key>(sk), order, id, V, Z,
                                       std::get<cpabbe::public_key>(pk), std::get<cpabbe::master_key>(mk));
            break;
            case CPABBE_S:
                cpabbe_s::key_generation(std::get<cpabbe_s::secret_key>(sk), order, id, V, Z,
                                         std::get<cpabbe_s::public_key>(pk), std::get<cpabbe_s::master_key>(mk));
            break;
        }
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& S, const std::vector<int>& J,
                    const std::vector<int>& V, const std::vector<int>& Z, const public_key& pk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                cpabbe::encryption(std::get<cpabbe::ciphertext>(ct), order, message, S, J, V, Z,
                                   std::get<cpabbe::public_key>(pk));
            break;
            case CPABBE_S:
                cpabbe_s::encryption(std::get<cpabbe_s::ciphertext>(ct), order, message, S, J, V, Z,
                                     std::get<cpabbe_s::public_key>(pk));
            break;
        }
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct,
                    const secret_key& sk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                cpabbe::decryption(message, order, std::get<cpabbe::ciphertext>(ct), std::get<cpabbe::secret_key>(sk));
            break;
            case CPABBE_S:
                cpabbe_s::decryption(message, order, std::get<cpabbe_s::ciphertext>(ct), std::get<cpabbe_s::secret_key>(sk));
            break;
        }
    }

    master_key init_master_key(const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                return cpabbe::master_key{};
            case CPABBE_S:
                return cpabbe_s::master_key{};
        }
        return cpabbe::master_key{};
    }

    public_key init_public_key(const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                return cpabbe::public_key{};
            case CPABBE_S:
                return cpabbe_s::public_key{};
        }
        return cpabbe::public_key{};
    }

    secret_key init_secret_key(const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                return cpabbe::secret_key{};
            case CPABBE_S:
                return cpabbe_s::secret_key{};
        }
        return cpabbe::secret_key{};
    }

    ciphertext init_ciphertext(const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                return cpabbe::ciphertext{};
            case CPABBE_S:
                return cpabbe_s::ciphertext{};
        }
        return cpabbe::ciphertext{};
    }

    void free_master_key(master_key& mk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                cpabbe::free_master_key(std::get<cpabbe::master_key>(mk));
            break;
            case CPABBE_S:
                cpabbe_s::free_master_key(std::get<cpabbe_s::master_key>(mk));
            break;
        }
    }

    void free_public_key(public_key& pk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                cpabbe::free_public_key(std::get<cpabbe::public_key>(pk));
            break;
            case CPABBE_S:
                cpabbe_s::free_public_key(std::get<cpabbe_s::public_key>(pk));
            break;
        }
    }

    void free_secret_key(secret_key& sk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                cpabbe::free_secret_key(std::get<cpabbe::secret_key>(sk));
            break;
            case CPABBE_S:
                cpabbe_s::free_secret_key(std::get<cpabbe_s::secret_key>(sk));
            break;
        }
    }

    void free_ciphertext(ciphertext& ct, const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                cpabbe::free_ciphertext(std::get<cpabbe::ciphertext>(ct));
            break;
            case CPABBE_S:
                cpabbe_s::free_ciphertext(std::get<cpabbe_s::ciphertext>(ct));
            break;
        }
    }

    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk, const abbe_type abbe_type) {
        switch(abbe_type) {
            case CPABBE:
                cpabbe::serialize_mk(data, std::get<cpabbe::master_key>(mk));
            break;
            case CPABBE_S:
                cpabbe_s::serialize_mk(data, std::get<cpabbe_s::master_key>(mk));
            break;
        }
    }

    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr, const abbe_type abbe_type) {
        master_key mk{};
        switch(abbe_type) {
            case CPABBE:
                return cpabbe::deserialize_mk(data, offset_ptr);
            case CPABBE_S:
                return cpabbe_s::deserialize_mk(data, offset_ptr);
        }
        return mk;
    }

    void test(const int id, const std::vector<int>& S, const std::vector<int>& J, const std::vector<int>& V,
              const std::vector<int>& Z, const std::vector<int>& Vprime, const std::vector<int>& Zprime,
              const abbe_type abbe_type) {
        // Setup
        bn_t order;
        bn_util_null_init(order);
        pc_get_ord(order);
        master_key mk = init_master_key(abbe_type);
        public_key pk = init_public_key(abbe_type);
        secret_key sk = init_secret_key(abbe_type);
        ciphertext ct = init_ciphertext(abbe_type);
        gt_t sent_message, received_message;
        gt_util_null_init(sent_message);
        gt_util_null_init(received_message);

        // Test
        gt_rand(sent_message);
        setup(mk, pk, order, abbe_type);
        key_generation(sk, order, id, Vprime, Zprime, pk, mk, abbe_type);
        encryption(ct, order, sent_message, S, J, V, Z, pk, abbe_type);
        decryption(received_message, order, ct, sk, abbe_type);

        const std::string abbe_type_string = type_to_string(abbe_type);
        if (gt_cmp(sent_message, received_message) == RLC_NE) {
            std::cerr << abbe_type_string << ": Received message does not match sent message" << std::endl;
        } else {
            std::cout << abbe_type_string << ": Received message matches sent message" << std::endl;
        }

        // Cleanup
        free_master_key(mk, abbe_type);
        free_public_key(pk, abbe_type);
        free_secret_key(sk, abbe_type);
        free_ciphertext(ct, abbe_type);
        gt_free(sent_message);
        gt_free(received_message);
        bn_free(order);
    }

    void measure_runtimes(const int id, const std::vector<int>& S, const std::vector<int>& J, const std::vector<int>& V,
                          const std::vector<int>& Z, const std::vector<int>& Vprime, const std::vector<int>& Zprime,
                          const int precision, const int repetitions, const abbe_type abbe_type) {
        // Setup
        bn_t order;
        bn_util_null_init(order);
        pc_get_ord(order);
        master_key mk = init_master_key(abbe_type);
        public_key pk = init_public_key(abbe_type);
        secret_key sk = init_secret_key(abbe_type);
        ciphertext ct = init_ciphertext(abbe_type);
        gt_t sent_message, received_message;
        gt_util_null_init(sent_message);
        gt_util_null_init(received_message);

        // Test
        std::chrono::steady_clock::time_point begin;
        std::chrono::steady_clock::time_point end;
        long setup_times[repetitions];
        long key_generation_times[repetitions];
        long encryption_times[repetitions];
        long decryption_times[repetitions];
        for (int i = 0; i < repetitions; ++i) {
            std::cout << i << "/" << repetitions << std::endl;
            gt_rand(sent_message);
            begin = std::chrono::steady_clock::now();
            setup(mk, pk, order, abbe_type);
            end = std::chrono::steady_clock::now();
            setup_times[i] = std::chrono::duration_cast<TIMER_PRECISION>(end - begin).count();
            begin = std::chrono::steady_clock::now();
            key_generation(sk, order, id, Vprime, Zprime, pk, mk, abbe_type);
            end = std::chrono::steady_clock::now();
            key_generation_times[i] = std::chrono::duration_cast<TIMER_PRECISION>(end - begin).count();
            begin = std::chrono::steady_clock::now();
            encryption(ct, order, sent_message, S, J, V, Z, pk, abbe_type);
            end = std::chrono::steady_clock::now();
            encryption_times[i] = std::chrono::duration_cast<TIMER_PRECISION>(end - begin).count();
            begin = std::chrono::steady_clock::now();
            decryption(received_message, order, ct, sk, abbe_type);
            end = std::chrono::steady_clock::now();
            decryption_times[i] = std::chrono::duration_cast<TIMER_PRECISION>(end - begin).count();
            free_master_key(mk, abbe_type);
            free_public_key(pk, abbe_type);
            free_secret_key(sk, abbe_type);
            free_ciphertext(ct, abbe_type);
        }

        auto [setup_mean, setup_stddev] = calculate_mean_stddev(setup_times, repetitions);
        auto [key_generation_mean, key_generation_stddev] = calculate_mean_stddev(key_generation_times, repetitions);
        auto [encryption_mean, encryption_stddev] = calculate_mean_stddev(encryption_times, repetitions);
        auto [decryption_mean, decryption_stddev] = calculate_mean_stddev(decryption_times, repetitions);
        if (isType<std::chrono::microseconds>(setup_mean)) {
            setup_mean /= 1000;
            setup_stddev /= 1000;
        }
        if (isType<std::chrono::microseconds>(key_generation_mean)) {
            key_generation_mean /= 1000;
            key_generation_stddev /= 1000;
        }
        if (isType<std::chrono::microseconds>(encryption_mean)) {
            encryption_mean /= 1000;
            encryption_stddev /= 1000;
        }
        if (isType<std::chrono::microseconds>(decryption_mean)) {
            decryption_mean /= 1000;
            decryption_stddev /= 1000;
        }
        const std::string abbe_type_string = type_to_string(abbe_type);
        std::cout << std::setprecision(precision) << std::fixed;
        std::cout << "%" << abbe_type_string << " Setup Time: " << setup_mean << " " << setup_stddev << std::endl;
        std::cout << "%" << abbe_type_string << " Key Generation Time: " << key_generation_mean << " " << key_generation_stddev << std::endl;
        std::cout << "%" << abbe_type_string << " Encryption Time: " << encryption_mean << " " << encryption_stddev << std::endl;
        std::cout << "%" << abbe_type_string << " Decryption Time: " << decryption_mean << " " << decryption_stddev << std::endl;

        // Cleanup
        gt_free(sent_message);
        gt_free(received_message);
        bn_free(order);
    }
}
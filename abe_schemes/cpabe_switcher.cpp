#include "cpabe_switcher.h"
#include <chrono>
#include <iomanip>

namespace cpabe_switcher {
    using TIMER_PRECISION = std::chrono::microseconds;
    // Needed for FAME CPABE
    constexpr int assump_size = 2;

    std::string type_to_string(const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                return "CPABE";
            case CPABE_S:
                return "CPABE S";
            case FAME_CPABE:
                return "FAME CPABE";
            case FABEO_CPABE:
                return "FABEO CPABE";
        }
        return "";
    }

    void setup(master_key& mk, public_key& pk, bn_t order, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::setup(std::get<cpabe::master_key>(mk), std::get<cpabe::public_key>(pk), order);
            break;
            case CPABE_S:
                cpabe_s::setup(std::get<cpabe_s::master_key>(mk), std::get<cpabe_s::public_key>(pk), order);
            break;
            case FAME_CPABE:
                fame_cpabe::setup(std::get<fame_cpabe::master_key>(mk),
                                  std::get<fame_cpabe::public_key>(pk), order, assump_size);
            break;
            case FABEO_CPABE:
                fabeo_cpabe::setup(std::get<fabeo_cpabe::master_key>(mk),
                                   std::get<fabeo_cpabe::public_key>(pk), order);
            break;
        }
    }

    void key_generation(secret_key& sk, bn_t order, const std::vector<int>& identity, const public_key& pk,
                        const master_key& mk, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::key_generation(std::get<cpabe::secret_key>(sk), order, identity,
                                      std::get<cpabe::master_key>(mk));
            break;
            case CPABE_S:
                cpabe_s::key_generation(std::get<cpabe_s::secret_key>(sk), order, identity,
                                        std::get<cpabe_s::master_key>(mk));
            break;
            case FAME_CPABE:
                fame_cpabe::key_generation(std::get<fame_cpabe::secret_key>(sk), order, identity,
                                           std::get<fame_cpabe::public_key>(pk),
                                           std::get<fame_cpabe::master_key>(mk));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::key_generation(std::get<fabeo_cpabe::secret_key>(sk), order, identity,
                                            std::get<fabeo_cpabe::master_key>(mk));
            break;
        }
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, TTree *policy, const public_key& pk, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::encryption(std::get<cpabe::ciphertext>(ct), order, message, policy,
                                  std::get<cpabe::public_key>(pk));
            break;
            case CPABE_S:
                cpabe_s::encryption(std::get<cpabe_s::ciphertext>(ct), order, message, policy,
                                    std::get<cpabe_s::public_key>(pk));
            break;
            case FAME_CPABE:
                fame_cpabe::encryption(std::get<fame_cpabe::ciphertext>(ct), order, message, policy,
                                       std::get<fame_cpabe::public_key>(pk));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::encryption(std::get<fabeo_cpabe::ciphertext>(ct), order, message, policy,
                                        std::get<fabeo_cpabe::public_key>(pk));
            break;
        }
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct,
                                   const secret_key& sk, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::decryption(message, order, std::get<cpabe::ciphertext>(ct), std::get<cpabe::secret_key>(sk));
            break;
            case CPABE_S:
                cpabe_s::decryption(message, order, std::get<cpabe_s::ciphertext>(ct), std::get<cpabe_s::secret_key>(sk));
            break;
            case FAME_CPABE:
                fame_cpabe::decryption(message, order, std::get<fame_cpabe::ciphertext>(ct),
                                       std::get<fame_cpabe::secret_key>(sk));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::decryption(message, order, std::get<fabeo_cpabe::ciphertext>(ct),
                                        std::get<fabeo_cpabe::secret_key>(sk));
            break;
        }
    }

    master_key init_master_key(const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                return cpabe::master_key{};
            case CPABE_S:
                return cpabe_s::master_key{};
            case FAME_CPABE:
                return fame_cpabe::master_key{};
            case FABEO_CPABE:
                return fabeo_cpabe::master_key{};
        }
        return cpabe::master_key{};
    }

    public_key init_public_key(const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                return cpabe::public_key{};
            case CPABE_S:
                return cpabe_s::public_key{};
            case FAME_CPABE:
                return fame_cpabe::public_key{};
            case FABEO_CPABE:
                return fabeo_cpabe::public_key{};
        }
        return cpabe::public_key{};
    }

    secret_key init_secret_key(const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                return cpabe::secret_key{};
            case CPABE_S:
                return cpabe_s::secret_key{};
            case FAME_CPABE:
                return fame_cpabe::secret_key{};
            case FABEO_CPABE:
                return fabeo_cpabe::secret_key{};
        }
        return cpabe::secret_key{};
    }

    ciphertext init_ciphertext(const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                return cpabe::ciphertext{};
            case CPABE_S:
                return cpabe_s::ciphertext{};
            case FAME_CPABE:
                return fame_cpabe::ciphertext{};
            case FABEO_CPABE:
                return fabeo_cpabe::ciphertext{};
        }
        return cpabe::ciphertext{};
    }

    void free_master_key(master_key& mk, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::free_master_key(std::get<cpabe::master_key>(mk));
            break;
            case CPABE_S:
                cpabe_s::free_master_key(std::get<cpabe_s::master_key>(mk));
            break;
            case FAME_CPABE:
                fame_cpabe::free_master_key(std::get<fame_cpabe::master_key>(mk));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::free_master_key(std::get<fabeo_cpabe::master_key>(mk));
            break;
        }
    }

    void free_public_key(public_key& pk, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::free_public_key(std::get<cpabe::public_key>(pk));
            break;
            case CPABE_S:
                cpabe_s::free_public_key(std::get<cpabe_s::public_key>(pk));
            break;
            case FAME_CPABE:
                fame_cpabe::free_public_key(std::get<fame_cpabe::public_key>(pk));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::free_public_key(std::get<fabeo_cpabe::public_key>(pk));
            break;
        }
    }

    void free_secret_key(secret_key& sk, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::free_secret_key(std::get<cpabe::secret_key>(sk));
            break;
            case CPABE_S:
                cpabe_s::free_secret_key(std::get<cpabe_s::secret_key>(sk));
            break;
            case FAME_CPABE:
                fame_cpabe::free_secret_key(std::get<fame_cpabe::secret_key>(sk));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::free_secret_key(std::get<fabeo_cpabe::secret_key>(sk));
            break;
        }
    }

    void free_ciphertext(ciphertext& ct, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::free_ciphertext(std::get<cpabe::ciphertext>(ct));
            break;
            case CPABE_S:
                cpabe_s::free_ciphertext(std::get<cpabe_s::ciphertext>(ct));
            break;
            case FAME_CPABE:
                fame_cpabe::free_ciphertext(std::get<fame_cpabe::ciphertext>(ct));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::free_ciphertext(std::get<fabeo_cpabe::ciphertext>(ct));
            break;
        }
    }

    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::serialize_mk(data, std::get<cpabe::master_key>(mk));
            break;
            case CPABE_S:
                cpabe_s::serialize_mk(data, std::get<cpabe_s::master_key>(mk));
            break;
            case FAME_CPABE:
                fame_cpabe::serialize_mk(data, std::get<fame_cpabe::master_key>(mk));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::serialize_mk(data, std::get<fabeo_cpabe::master_key>(mk));
            break;
        }
    }

    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr, const abe_type abe_type) {
        master_key mk{};
        switch(abe_type) {
            case CPABE:
                return cpabe::deserialize_mk(data, offset_ptr);
            case CPABE_S:
                return cpabe_s::deserialize_mk(data, offset_ptr);
            case FAME_CPABE:
                return fame_cpabe::deserialize_mk(data, offset_ptr);
            case FABEO_CPABE:
                return fabeo_cpabe::deserialize_mk(data, offset_ptr);
        }
        return mk;
    }

    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk, const abe_type abe_type) {
        switch(abe_type) {
            case CPABE:
                cpabe::serialize_pk(data, std::get<cpabe::public_key>(pk));
            break;
            case CPABE_S:
                cpabe_s::serialize_pk(data, std::get<cpabe_s::public_key>(pk));
            break;
            case FAME_CPABE:
                fame_cpabe::serialize_pk(data, std::get<fame_cpabe::public_key>(pk));
            break;
            case FABEO_CPABE:
                fabeo_cpabe::serialize_pk(data, std::get<fabeo_cpabe::public_key>(pk));
            break;
        }
    }

    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr, const abe_type abe_type) {
        public_key pk{};
        switch(abe_type) {
            case CPABE:
                return cpabe::deserialize_pk(data, offset_ptr);
            case CPABE_S:
                return cpabe_s::deserialize_pk(data, offset_ptr);
            case FAME_CPABE:
                return fame_cpabe::deserialize_pk(data, offset_ptr);
            case FABEO_CPABE:
                return fabeo_cpabe::deserialize_pk(data, offset_ptr);
        }
        return pk;
    }

    void test(TTree *publisher_policy, const std::vector<int>& recipient_id, const abe_type abe_type) {
        // Setup
        bn_t order;
        bn_util_null_init(order);
        pc_get_ord(order);
        master_key mk = init_master_key(abe_type);
        public_key pk = init_public_key(abe_type);
        secret_key sk = init_secret_key(abe_type);
        ciphertext ct = init_ciphertext(abe_type);
        gt_t sent_message, received_message;
        gt_util_null_init(sent_message);
        gt_util_null_init(received_message);

        // Test
        gt_rand(sent_message);
        setup(mk, pk, order, abe_type);
        key_generation(sk, order, recipient_id, pk, mk, abe_type);
        encryption(ct, order, sent_message, publisher_policy, pk, abe_type);
        decryption(received_message, order, ct, sk, abe_type);

        const std::string abe_type_string = type_to_string(abe_type);
        if (gt_cmp(sent_message, received_message) == RLC_NE) {
            std::cerr << abe_type_string << ": Received message does not match sent message" << std::endl;
        } else {
            std::cout << abe_type_string << ": Received message matches sent message" << std::endl;
        }

        // Cleanup
        free_master_key(mk, abe_type);
        free_public_key(pk, abe_type);
        free_secret_key(sk, abe_type);
        free_ciphertext(ct, abe_type);
        gt_free(sent_message);
        gt_free(received_message);
        bn_free(order);
    }

    void measure_runtimes(TTree *publisher_policy, const std::vector<int>& recipient_id, const int precision, const int repetitions, const abe_type abe_type) {
        // Setup
        bn_t order;
        bn_util_null_init(order);
        pc_get_ord(order);
        master_key mk = init_master_key(abe_type);
        public_key pk = init_public_key(abe_type);
        secret_key sk = init_secret_key(abe_type);
        ciphertext ct = init_ciphertext(abe_type);
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
            setup(mk, pk, order, abe_type);
            end = std::chrono::steady_clock::now();
            setup_times[i] = std::chrono::duration_cast<TIMER_PRECISION>(end - begin).count();
            begin = std::chrono::steady_clock::now();
            key_generation(sk, order, recipient_id, pk, mk, abe_type);
            end = std::chrono::steady_clock::now();
            key_generation_times[i] = std::chrono::duration_cast<TIMER_PRECISION>(end - begin).count();
            free_master_key(mk, abe_type);
            begin = std::chrono::steady_clock::now();
            encryption(ct, order, sent_message, publisher_policy, pk, abe_type);
            end = std::chrono::steady_clock::now();
            encryption_times[i] = std::chrono::duration_cast<TIMER_PRECISION>(end - begin).count();
            free_public_key(pk, abe_type);
            begin = std::chrono::steady_clock::now();
            decryption(received_message, order, ct, sk, abe_type);
            end = std::chrono::steady_clock::now();
            decryption_times[i] = std::chrono::duration_cast<TIMER_PRECISION>(end - begin).count();
            free_secret_key(sk, abe_type);
            free_ciphertext(ct, abe_type);
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
        const std::string abe_type_string = type_to_string(abe_type);
        std::cout << std::setprecision(precision) << std::fixed;
        std::cout << "%" << abe_type_string << " Setup Time: " << setup_mean << " " << setup_stddev << std::endl;
        std::cout << "%" << abe_type_string << " Key Generation Time: " << key_generation_mean << " " << key_generation_stddev << std::endl;
        std::cout << "%" << abe_type_string << " Encryption Time: " << encryption_mean << " " << encryption_stddev << std::endl;
        std::cout << "%" << abe_type_string << " Decryption Time: " << decryption_mean << " " << decryption_stddev << std::endl;

        // Cleanup
        gt_free(sent_message);
        gt_free(received_message);
        bn_free(order);
    }
}
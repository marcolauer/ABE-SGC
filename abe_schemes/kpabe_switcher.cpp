#include "kpabe_switcher.h"
#include <chrono>
#include <iomanip>
#include "../config.h"

namespace kpabe_switcher {
    using TIMER_PRECISION = std::chrono::microseconds;
    // Needed for FIBE, KPABE
    // Maximum number of exisiting attributes
    constexpr int universe_size = MASTER_UNIVERSE_SIZE;
    // Needed for FIBE LARGE, KPABE LARGE
    // Maximum length of the identities
    constexpr int universe_n = MASTER_UNIVERSE_SIZE;
    // Needed for FAME KPABE
    constexpr int assump_size = 2;

    std::pair<int, std::vector<int>> generate_fibe_policy(TTree *policy) {
        if (isType<TAttribute>(*policy)) {
            return {1, std::vector{dynamic_cast<TAttribute *>(policy)->get_attribute()}};
        }
        const auto tThreshold = dynamic_cast<TThreshold*>(policy);
        std::pair<int, std::vector<int>> result;
        result.first = tThreshold->get_t();
        for (const auto child : tThreshold->get_children()) {
            if (isType<TThreshold>(*child)) {
                std::cerr << "Policy invalid for FIBE";
                exit(-1);
            }
            result.second.push_back(dynamic_cast<TAttribute *>(child)->get_attribute());
        }
        return result;
    }

    std::string type_to_string(const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                return "FIBE";
            case FIBE_S:
                return "FIBE S";
            case FIBE_LARGE:
                return "FIBE LARGE";
            case FIBE_LARGE_S:
                return "FIBE LARGE S";
            case KPABE:
                return "KPABE";
            case KPABE_S:
                return "KPABE S";
            case KPABE_LARGE:
                return "KPABE LARGE";
            case KPABE_LARGE_S:
                return "KPABE LARGE S";
            case FAME_KPABE:
                return "FAME KPABE";
            case FABEO_KPABE:
                return "FABEO KPABE";
        }
        return "";
    }

    void setup(master_key& mk, public_key& pk, bn_t order, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::setup(std::get<fibe::master_key>(mk), std::get<fibe::public_key>(pk), order,
                            universe_size);
            break;
            case FIBE_S:
                fibe_s::setup(std::get<fibe_s::master_key>(mk), std::get<fibe_s::public_key>(pk), order,
                              universe_size);
            break;
            case FIBE_LARGE:
                fibe_large::setup(std::get<fibe_large::master_key>(mk),
                                  std::get<fibe_large::public_key>(pk), order, universe_n);
            break;
            case FIBE_LARGE_S:
                fibe_large_s::setup(std::get<fibe_large_s::master_key>(mk),
                                    std::get<fibe_large_s::public_key>(pk), order, universe_n);
            break;
            case KPABE:
                kpabe::setup(std::get<kpabe::master_key>(mk), std::get<kpabe::public_key>(pk), order,
                             universe_size);
            break;
            case KPABE_S:
                kpabe_s::setup(std::get<kpabe_s::master_key>(mk), std::get<kpabe_s::public_key>(pk), order,
                               universe_size);
            break;
            case KPABE_LARGE:
                kpabe_large::setup(std::get<kpabe_large::master_key>(mk),
                                   std::get<kpabe_large::public_key>(pk), order, universe_n);
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::setup(std::get<kpabe_large_s::master_key>(mk),
                                     std::get<kpabe_large_s::public_key>(pk), order, universe_n);
            break;
            case FAME_KPABE:
                fame_kpabe::setup(std::get<fame_kpabe::master_key>(mk),
                                  std::get<fame_kpabe::public_key>(pk), order, assump_size);
            break;
            case FABEO_KPABE:
                fabeo_kpabe::setup(std::get<fabeo_kpabe::master_key>(mk),
                                   std::get<fabeo_kpabe::public_key>(pk), order);
            break;
        }
    }

    void key_generation(secret_key& sk, bn_t order, TTree *policy, const public_key& pk, const master_key& mk,
                        const abe_type abe_type) {
        switch(abe_type) {
            case FIBE: {
                const auto [d, identity] = generate_fibe_policy(policy);
                fibe::key_generation(std::get<fibe::secret_key>(sk), order, d, identity,
                                     std::get<fibe::master_key>(mk));
            }
            break;
            case FIBE_S: {
                const auto [d, identity] = generate_fibe_policy(policy);
                fibe_s::key_generation(std::get<fibe_s::secret_key>(sk), order, d, identity,
                                       std::get<fibe_s::master_key>(mk));
            }
            break;
            case FIBE_LARGE: {
                const auto [d, identity] = generate_fibe_policy(policy);
                fibe_large::key_generation(std::get<fibe_large::secret_key>(sk), order, d, identity,
                                           std::get<fibe_large::public_key>(pk),
                                           std::get<fibe_large::master_key>(mk));
            }
            break;
            case FIBE_LARGE_S: {
                const auto [d, identity] = generate_fibe_policy(policy);
                fibe_large_s::key_generation(std::get<fibe_large_s::secret_key>(sk), order, d, identity,
                                             std::get<fibe_large_s::public_key>(pk),
                                             std::get<fibe_large_s::master_key>(mk));
            }
            break;
            case KPABE:
                kpabe::key_generation(std::get<kpabe::secret_key>(sk), order, policy,
                                      std::get<kpabe::master_key>(mk));
            break;
            case KPABE_S:
                kpabe_s::key_generation(std::get<kpabe_s::secret_key>(sk), order, policy,
                                        std::get<kpabe_s::master_key>(mk));
            break;
            case KPABE_LARGE:
                kpabe_large::key_generation(std::get<kpabe_large::secret_key>(sk), order, policy,
                                            std::get<kpabe_large::public_key>(pk),
                                            std::get<kpabe_large::master_key>(mk));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::key_generation(std::get<kpabe_large_s::secret_key>(sk), order, policy,
                                              std::get<kpabe_large_s::public_key>(pk),
                                              std::get<kpabe_large_s::master_key>(mk));
            break;
            case FAME_KPABE:
                fame_kpabe::key_generation(std::get<fame_kpabe::secret_key>(sk), order, policy,
                                           std::get<fame_kpabe::public_key>(pk),
                                           std::get<fame_kpabe::master_key>(mk));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::key_generation(std::get<fabeo_kpabe::secret_key>(sk), order, policy,
                                            std::get<fabeo_kpabe::master_key>(mk));
            break;
        }
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& identity, const public_key& pk,
                    const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::encryption(std::get<fibe::ciphertext>(ct), order, message, identity,
                                 std::get<fibe::public_key>(pk));
            break;
            case FIBE_S:
                fibe_s::encryption(std::get<fibe_s::ciphertext>(ct), order, message, identity,
                                   std::get<fibe_s::public_key>(pk));
            break;
            case FIBE_LARGE:
                fibe_large::encryption(std::get<fibe_large::ciphertext>(ct), order, message, identity,
                                       std::get<fibe_large::public_key>(pk));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::encryption(std::get<fibe_large_s::ciphertext>(ct), order, message, identity,
                                         std::get<fibe_large_s::public_key>(pk));
            break;
            case KPABE:
                kpabe::encryption(std::get<kpabe::ciphertext>(ct), order, message, identity,
                                  std::get<kpabe::public_key>(pk));
            break;
            case KPABE_S:
                kpabe_s::encryption(std::get<kpabe_s::ciphertext>(ct), order, message, identity,
                                    std::get<kpabe_s::public_key>(pk));
            break;
            case KPABE_LARGE:
                kpabe_large::encryption(std::get<kpabe_large::ciphertext>(ct), order, message, identity,
                                        std::get<kpabe_large::public_key>(pk));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::encryption(std::get<kpabe_large_s::ciphertext>(ct), order, message, identity,
                                          std::get<kpabe_large_s::public_key>(pk));
            break;
            case FAME_KPABE:
                fame_kpabe::encryption(std::get<fame_kpabe::ciphertext>(ct), order, message, identity,
                                       std::get<fame_kpabe::public_key>(pk));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::encryption(std::get<fabeo_kpabe::ciphertext>(ct), order, message, identity,
                                        std::get<fabeo_kpabe::public_key>(pk));
            break;
        }
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::decryption(message, order, std::get<fibe::ciphertext>(ct), std::get<fibe::secret_key>(sk));
            break;
            case FIBE_S:
                fibe_s::decryption(message, order, std::get<fibe_s::ciphertext>(ct), std::get<fibe_s::secret_key>(sk));
            break;
            case FIBE_LARGE:
                fibe_large::decryption(message, order, std::get<fibe_large::ciphertext>(ct),
                                       std::get<fibe_large::secret_key>(sk));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::decryption(message, order, std::get<fibe_large_s::ciphertext>(ct),
                                         std::get<fibe_large_s::secret_key>(sk));
            break;
            case KPABE:
                kpabe::decryption(message, order, std::get<kpabe::ciphertext>(ct), std::get<kpabe::secret_key>(sk));
            break;
            case KPABE_S:
                kpabe_s::decryption(message, order, std::get<kpabe_s::ciphertext>(ct), std::get<kpabe_s::secret_key>(sk));
            break;
            case KPABE_LARGE:
                kpabe_large::decryption(message, order, std::get<kpabe_large::ciphertext>(ct),
                                        std::get<kpabe_large::secret_key>(sk));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::decryption(message, order, std::get<kpabe_large_s::ciphertext>(ct),
                                          std::get<kpabe_large_s::secret_key>(sk));
            break;
            case FAME_KPABE:
                fame_kpabe::decryption(message, order, std::get<fame_kpabe::ciphertext>(ct),
                                       std::get<fame_kpabe::secret_key>(sk));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::decryption(message, order, std::get<fabeo_kpabe::ciphertext>(ct),
                                        std::get<fabeo_kpabe::secret_key>(sk));
            break;
        }
    }

    master_key init_master_key(const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                return fibe::master_key{};
            case FIBE_S:
                return fibe_s::master_key{};
            case FIBE_LARGE:
                return fibe_large::master_key{};
            case FIBE_LARGE_S:
                return fibe_large_s::master_key{};
            case KPABE:
                return kpabe::master_key{};
            case KPABE_S:
                return kpabe_s::master_key{};
            case KPABE_LARGE:
                return kpabe_large::master_key{};
            case KPABE_LARGE_S:
                return kpabe_large_s::master_key{};
            case FAME_KPABE:
                return fame_kpabe::master_key{};
            case FABEO_KPABE:
                return fabeo_kpabe::master_key{};
        }
        return fibe::master_key{};
    }

    public_key init_public_key(const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                return fibe::public_key{};
            case FIBE_S:
                return fibe_s::public_key{};
            case FIBE_LARGE:
                return fibe_large::public_key{};
            case FIBE_LARGE_S:
                return fibe_large_s::public_key{};
            case KPABE:
                return kpabe::public_key{};
            case KPABE_S:
                return kpabe_s::public_key{};
            case KPABE_LARGE:
                return kpabe_large::public_key{};
            case KPABE_LARGE_S:
                return kpabe_large_s::public_key{};
            case FAME_KPABE:
                return fame_kpabe::public_key{};
            case FABEO_KPABE:
                return fabeo_kpabe::public_key{};
        }
        return fibe::public_key{};
    }

    secret_key init_secret_key(const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                return fibe::secret_key{};
            case FIBE_S:
                return fibe_s::secret_key{};
            case FIBE_LARGE:
                return fibe_large::secret_key{};
            case FIBE_LARGE_S:
                return fibe_large_s::secret_key{};
            case KPABE:
                return kpabe::secret_key{};
            case KPABE_S:
                return kpabe_s::secret_key{};
            case KPABE_LARGE:
                return kpabe_large::secret_key{};
            case KPABE_LARGE_S:
                return kpabe_large_s::secret_key{};
            case FAME_KPABE:
                return fame_kpabe::secret_key{};
            case FABEO_KPABE:
                return fabeo_kpabe::secret_key{};
        }
        return fibe::secret_key{};
    }

    ciphertext init_ciphertext(const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                return fibe::ciphertext{};
            case FIBE_S:
                return fibe_s::ciphertext{};
            case FIBE_LARGE:
                return fibe_large::ciphertext{};
            case FIBE_LARGE_S:
                return fibe_large_s::ciphertext{};
            case KPABE:
                return kpabe::ciphertext{};
            case KPABE_S:
                return kpabe_s::ciphertext{};
            case KPABE_LARGE:
                return kpabe_large::ciphertext{};
            case KPABE_LARGE_S:
                return kpabe_large_s::ciphertext{};
            case FAME_KPABE:
                return fame_kpabe::ciphertext{};
            case FABEO_KPABE:
                return fabeo_kpabe::ciphertext{};
        }
        return fibe::ciphertext{};
    }

    void free_master_key(master_key& mk, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::free_master_key(std::get<fibe::master_key>(mk));
            break;
            case FIBE_S:
                fibe_s::free_master_key(std::get<fibe_s::master_key>(mk));
            break;
            case FIBE_LARGE:
                fibe_large::free_master_key(std::get<fibe_large::master_key>(mk));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::free_master_key(std::get<fibe_large_s::master_key>(mk));
            break;
            case KPABE:
                kpabe::free_master_key(std::get<kpabe::master_key>(mk));
            break;
            case KPABE_S:
                kpabe_s::free_master_key(std::get<kpabe_s::master_key>(mk));
            break;
            case KPABE_LARGE:
                kpabe_large::free_master_key(std::get<kpabe_large::master_key>(mk));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::free_master_key(std::get<kpabe_large_s::master_key>(mk));
            break;
            case FAME_KPABE:
                fame_kpabe::free_master_key(std::get<fame_kpabe::master_key>(mk));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::free_master_key(std::get<fabeo_kpabe::master_key>(mk));
            break;
        }
    }

    void free_public_key(public_key& pk, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::free_public_key(std::get<fibe::public_key>(pk));
            break;
            case FIBE_S:
                fibe_s::free_public_key(std::get<fibe_s::public_key>(pk));
            break;
            case FIBE_LARGE:
                fibe_large::free_public_key(std::get<fibe_large::public_key>(pk));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::free_public_key(std::get<fibe_large_s::public_key>(pk));
            break;
            case KPABE:
                kpabe::free_public_key(std::get<kpabe::public_key>(pk));
            break;
            case KPABE_S:
                kpabe_s::free_public_key(std::get<kpabe_s::public_key>(pk));
            break;
            case KPABE_LARGE:
                kpabe_large::free_public_key(std::get<kpabe_large::public_key>(pk));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::free_public_key(std::get<kpabe_large_s::public_key>(pk));
            break;
            case FAME_KPABE:
                fame_kpabe::free_public_key(std::get<fame_kpabe::public_key>(pk));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::free_public_key(std::get<fabeo_kpabe::public_key>(pk));
            break;
        }
    }

    void free_secret_key(secret_key& sk, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::free_secret_key(std::get<fibe::secret_key>(sk));
            break;
            case FIBE_S:
                fibe_s::free_secret_key(std::get<fibe_s::secret_key>(sk));
            break;
            case FIBE_LARGE:
                fibe_large::free_secret_key(std::get<fibe_large::secret_key>(sk));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::free_secret_key(std::get<fibe_large_s::secret_key>(sk));
            break;
            case KPABE:
                kpabe::free_secret_key(std::get<kpabe::secret_key>(sk));
            break;
            case KPABE_S:
                kpabe_s::free_secret_key(std::get<kpabe_s::secret_key>(sk));
            break;
            case KPABE_LARGE:
                kpabe_large::free_secret_key(std::get<kpabe_large::secret_key>(sk));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::free_secret_key(std::get<kpabe_large_s::secret_key>(sk));
            break;
            case FAME_KPABE:
                fame_kpabe::free_secret_key(std::get<fame_kpabe::secret_key>(sk));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::free_secret_key(std::get<fabeo_kpabe::secret_key>(sk));
            break;
        }
    }

    void free_ciphertext(ciphertext& ct, const abe_type abe_type) {
        switch(abe_type) {
            case FIBE:
                fibe::free_ciphertext(std::get<fibe::ciphertext>(ct));
            break;
            case FIBE_S:
                fibe_s::free_ciphertext(std::get<fibe_s::ciphertext>(ct));
            break;
            case FIBE_LARGE:
                fibe_large::free_ciphertext(std::get<fibe_large::ciphertext>(ct));
            break;
            case FIBE_LARGE_S:
                fibe_large_s::free_ciphertext(std::get<fibe_large_s::ciphertext>(ct));
            break;
            case KPABE:
                kpabe::free_ciphertext(std::get<kpabe::ciphertext>(ct));
            break;
            case KPABE_S:
                kpabe_s::free_ciphertext(std::get<kpabe_s::ciphertext>(ct));
            break;
            case KPABE_LARGE:
                kpabe_large::free_ciphertext(std::get<kpabe_large::ciphertext>(ct));
            break;
            case KPABE_LARGE_S:
                kpabe_large_s::free_ciphertext(std::get<kpabe_large_s::ciphertext>(ct));
            break;
            case FAME_KPABE:
                fame_kpabe::free_ciphertext(std::get<fame_kpabe::ciphertext>(ct));
            break;
            case FABEO_KPABE:
                fabeo_kpabe::free_ciphertext(std::get<fabeo_kpabe::ciphertext>(ct));
            break;
        }
    }

    void test(const std::vector<int>& publisher_id, TTree *recipient_policy, const abe_type abe_type) {
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
        key_generation(sk, order, recipient_policy, pk, mk, abe_type);
        encryption(ct, order, sent_message, publisher_id, pk, abe_type);
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

    void measure_runtimes(const std::vector<int>& publisher_id, TTree *recipient_policy, const int precision, const int repetitions, const abe_type abe_type) {
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
            key_generation(sk, order, recipient_policy, pk, mk, abe_type);
            end = std::chrono::steady_clock::now();
            key_generation_times[i] = std::chrono::duration_cast<TIMER_PRECISION>(end - begin).count();
            free_master_key(mk, abe_type);
            begin = std::chrono::steady_clock::now();
            encryption(ct, order, sent_message, publisher_id, pk, abe_type);
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
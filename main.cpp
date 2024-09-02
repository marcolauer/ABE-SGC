#include <string>
#include <iostream>
#include <chrono>
#include "random.h"
#include "config.h"

#include "abe_schemes/kpabbe.h"
#include "abe_schemes/cpabbe.h"
#include "abe_schemes/kpabe_switcher.h"
#include "abe_schemes/cpabe_switcher.h"

#include "reference_sgc_schemes/skdc.h"
#include "reference_sgc_schemes/lkh.h"
#include "reference_sgc_schemes/s2rp.h"

#include "abe_sgc_schemes/flat_table.h"
#include "abe_sgc_schemes/flat_table.h"
#include "abe_sgc_schemes/naive_cpabe.h"
#include "abe_sgc_schemes/naive_cpabe.h"
#include "abe_sgc_schemes/naive_kpabe.h"
#include "abe_schemes/kpabbe.h"
#include "abe_schemes/cpabbe.h"
#include "abe_sgc_schemes/kpabbe_sgc.h"
#include "abe_sgc_schemes/cpabbe_sgc.h"

#if MASTER_DEVICE == MASTER_ESP32
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_spiffs.h"
#endif

enum main_action {
    RUN_GC,           // Run Group Controller (GC) operations
    RUN_GM,           // Run Group Member (GC) operations
    SAVE_MESSAGES,    // Generate Message files for RUN_GM
    MEASURE_MSG_SIZES // Measure the sizes of the update messages
};

void program(void *pvParameter);

#if MASTER_DEVICE == MASTER_PC
int main() {
    program(nullptr);
    return 0;
}
#elif MASTER_DEVICE == MASTER_ESP32
extern "C" void app_main(void) {
    xTaskCreate(&program, "mainfunc", 40000, NULL, 1, NULL);
}
#endif

void program(void *pvParameter) {
    // Setup
#if MASTER_DEVICE == MASTER_ESP32
    esp_vfs_spiffs_conf_t config = {
        .base_path = "/storage",
        .partition_label = NULL,
        .max_files = 1,
        .format_if_mount_failed = true
    };
    esp_vfs_spiffs_register(&config);
#endif
    core_init();
    pc_param_set_any();

    // General Parameters
    constexpr int precision = 2;        // Decimal places of runtime measurements
    constexpr int repetitions = 100;    // Number of runtime measurement repetitions

    // Parameters for evaluating ABE schemes
    int num_attrs = 10;                 // Number of attributes for evaluation of ABE schemes

    std::vector<TTree *> children1;
    children1.reserve(num_attrs);
    for (int i = 0; i < num_attrs; ++i) {
        children1.push_back(new TAttribute(i+1));
    }
    std::vector<TTree *> children2;
    children2.reserve(num_attrs);
    for (int i = 0; i < num_attrs; ++i) {
        children2.push_back(new TAttribute(i+1));
    }
    std::vector<int> kpabe_publisher_id(num_attrs); // 1 to 100
    std::iota(kpabe_publisher_id.begin(), kpabe_publisher_id.end(), 1);
    const auto kpabe_recipient_policy = new TThreshold(num_attrs, num_attrs, children1);
    std::vector<int> cpabe_recipient_id(num_attrs); // 1 to 100
    std::iota(cpabe_recipient_id.begin(), cpabe_recipient_id.end(), 1);
    const auto cpabe_publisher_policy = new TThreshold(num_attrs, num_attrs, children2);

    constexpr int id = 1;
    std::vector<int> S(num_attrs); // 1 to 100
    std::iota(S.begin(), S.end(), 1);
    std::vector<int> kpabbe_V(num_attrs);
    std::iota(kpabbe_V.begin(), kpabbe_V.end(), 1);
    std::vector<int> kpabbe_Z{};
    std::vector<int> kpabbe_J{};
    std::vector<int> kpabbe_Vprime(num_attrs);
    std::iota(kpabbe_Vprime.begin(), kpabbe_Vprime.end(), 1);
    std::vector<int> kpabbe_Zprime{};

    const std::vector<int> cpabbe_J{};
    std::vector<int> cpabbe_V(num_attrs);
    std::iota(cpabbe_V.begin(), cpabbe_V.end(), 1);
    std::vector<int> cpabbe_Z{};
    std::vector<int> cpabbe_Vprime(num_attrs);
    std::iota(cpabbe_Vprime.begin(), cpabbe_Vprime.end(), 1);
    std::vector<int> cpabbe_Zprime{};

    // Parameters for evaluating SGC schemes
    constexpr main_action action = RUN_GC;          // See top of this file
    constexpr int group_size = 100;                 // Size of the SGC group
    constexpr int byte_length = 16;                 // Byte length of the symmetric keys
    constexpr int degree = 4;                       // Degree of the Key Trees for LKH and S2RP
    constexpr int chain_length = 10;                // Hash chain length for S2RP

    // Test BLS12-381 basic operation times

    std::chrono::steady_clock::time_point begin;
    std::chrono::steady_clock::time_point end;
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);
    bn_t temp_bn;
    bn_util_null_init(temp_bn);
    g1_t temp_g1, temp_g1_2;
    g1_util_null_init(temp_g1);
    g1_util_null_init(temp_g1_2);
    g2_t temp_g2, temp_g2_2;
    g2_util_null_init(temp_g2);
    g2_util_null_init(temp_g2_2);
    gt_t temp_gt, temp_gt_2;
    gt_util_null_init(temp_gt);
    gt_util_null_init(temp_gt_2);
    int hash_input[3];
    hash_input[0] = 1;
    hash_input[1] = 2;
    hash_input[2] = 3;
    long g1_add_times[repetitions];
    long g2_add_times[repetitions];
    long gt_mul_times[repetitions];
    long g1_mul_times[repetitions];
    long g2_mul_times[repetitions];
    long gt_exp_times[repetitions];
    long g1_hash_times[repetitions];
    long g2_hash_times[repetitions];
    long pairing_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        bn_rand_mod(temp_bn, order);
        g1_rand(temp_g1);
        g1_rand(temp_g1_2);
        g2_rand(temp_g2);
        g2_rand(temp_g2_2);
        gt_rand(temp_gt);
        gt_rand(temp_gt_2);
        begin = std::chrono::steady_clock::now();
        g1_add(temp_g1, temp_g1, temp_g1_2);
        end = std::chrono::steady_clock::now();
        g1_add_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        begin = std::chrono::steady_clock::now();
        g2_add(temp_g2, temp_g2, temp_g2_2);
        end = std::chrono::steady_clock::now();
        g2_add_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        begin = std::chrono::steady_clock::now();
        gt_mul(temp_gt, temp_gt, temp_gt_2);
        end = std::chrono::steady_clock::now();
        gt_mul_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        begin = std::chrono::steady_clock::now();
        g1_mul(temp_g1, temp_g1_2, temp_bn);
        end = std::chrono::steady_clock::now();
        g1_mul_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        begin = std::chrono::steady_clock::now();
        g2_mul(temp_g2, temp_g2_2, temp_bn);
        end = std::chrono::steady_clock::now();
        g2_mul_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        begin = std::chrono::steady_clock::now();
        gt_exp(temp_gt, temp_gt_2, temp_bn);
        end = std::chrono::steady_clock::now();
        gt_exp_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        begin = std::chrono::steady_clock::now();
        g1_map(temp_g1, static_cast<const uint8_t *>(static_cast<void *>(&hash_input)), 3 * sizeof(int));
        end = std::chrono::steady_clock::now();
        g1_hash_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        begin = std::chrono::steady_clock::now();
        g2_map(temp_g2, static_cast<const uint8_t *>(static_cast<void *>(&hash_input)), 3 * sizeof(int));
        end = std::chrono::steady_clock::now();
        g2_hash_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        begin = std::chrono::steady_clock::now();
        pc_map(temp_gt, temp_g1, temp_g2);
        end = std::chrono::steady_clock::now();
        pairing_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }
    auto [g1_add_mean, g1_add_stddev] = calculate_mean_stddev(g1_add_times, repetitions);
    auto [g2_add_mean, g2_add_stddev] = calculate_mean_stddev(g2_add_times, repetitions);
    auto [gt_mul_mean, gt_mul_stddev] = calculate_mean_stddev(gt_mul_times, repetitions);
    auto [g1_mul_mean, g1_mul_stddev] = calculate_mean_stddev(g1_mul_times, repetitions);
    auto [g2_mul_mean, g2_mul_stddev] = calculate_mean_stddev(g2_mul_times, repetitions);
    auto [gt_exp_mean, gt_exp_stddev] = calculate_mean_stddev(gt_exp_times, repetitions);
    auto [g1_hash_mean, g1_hash_stddev] = calculate_mean_stddev(g1_hash_times, repetitions);
    auto [g2_hash_mean, g2_hash_stddev] = calculate_mean_stddev(g2_hash_times, repetitions);
    auto [pairing_mean, pairing_stddev] = calculate_mean_stddev(pairing_times, repetitions);
    std::cout << "G1 Add Time: " << g1_add_mean << " " << g1_add_stddev << std::endl;
    std::cout << "G2 Add Time: " << g2_add_mean << " " << g2_add_stddev << std::endl;
    std::cout << "GT Mul Time: " << gt_mul_mean << " " << gt_mul_stddev << std::endl;
    std::cout << "G1 Mul Time: " << g1_mul_mean << " " << g1_mul_stddev << std::endl;
    std::cout << "G2 Mul Time: " << g2_mul_mean << " " << g2_mul_stddev << std::endl;
    std::cout << "GT Exp Time: " << gt_exp_mean << " " << gt_exp_stddev << std::endl;
    std::cout << "G1 Hash Time: " << g1_hash_mean << " " << g1_hash_stddev << std::endl;
    std::cout << "G2 Hash Time: " << g2_hash_mean << " " << g2_hash_stddev << std::endl;
    std::cout << "Pairing Time: " << pairing_mean << " " << pairing_stddev << std::endl;
    bn_free(temp_bn);
    bn_free(order);
    g1_free(temp_g1);
    g1_free(temp_g1_2);
    g2_free(temp_g2);
    g2_free(temp_g2_2);
    gt_free(temp_gt);
    gt_free(temp_gt_2);
    //*/

    // Test RELIC ABE Schemes
    /*
    std::cout << "ABE RELIC Tests:" << std::endl;
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FIBE);
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FIBE_S);
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FIBE_LARGE);
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FIBE_LARGE_S);
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::KPABE);
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::KPABE_S);
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::KPABE_LARGE);
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::KPABE_LARGE_S);
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FAME_KPABE);
    test(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FABEO_KPABE);
    test(cpabe_publisher_policy, cpabe_recipient_id, cpabe_switcher::CPABE);
    test(cpabe_publisher_policy, cpabe_recipient_id, cpabe_switcher::CPABE_S);
    test(cpabe_publisher_policy, cpabe_recipient_id, cpabe_switcher::FAME_CPABE);
    test(cpabe_publisher_policy, cpabe_recipient_id, cpabe_switcher::FABEO_CPABE);
    test(id, S, kpabbe_V, kpabbe_Z, kpabbe_J, kpabbe_Vprime, kpabbe_Zprime, kpabbe_switcher::KPABBE);
    test(id, S, kpabbe_V, kpabbe_Z, kpabbe_J, kpabbe_Vprime, kpabbe_Zprime, kpabbe_switcher::KPABBE_S);
    test(id, S, cpabbe_J, cpabbe_V, cpabbe_Z, cpabbe_Vprime, cpabbe_Zprime, cpabbe_switcher::CPABBE);
    test(id, S, cpabbe_J, cpabbe_V, cpabbe_Z, cpabbe_Vprime, cpabbe_Zprime, cpabbe_switcher::CPABBE_S);
    //*/

    // Run RELIC ABE Schemes
    /*
    std::cout << "ABE RELIC Runtimes:" << std::endl;
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::FIBE);
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::FIBE_S);
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::FIBE_LARGE);
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::FIBE_LARGE_S);
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::KPABE);
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::KPABE_S);
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::KPABE_LARGE);
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::KPABE_LARGE_S);
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::FAME_KPABE);
    measure_runtimes(kpabe_publisher_id, kpabe_recipient_policy, precision, repetitions, kpabe_switcher::FABEO_KPABE);
    measure_runtimes(cpabe_publisher_policy, cpabe_recipient_id, precision, repetitions, cpabe_switcher::CPABE);
    measure_runtimes(cpabe_publisher_policy, cpabe_recipient_id, precision, repetitions, cpabe_switcher::CPABE_S);
    measure_runtimes(cpabe_publisher_policy, cpabe_recipient_id, precision, repetitions, cpabe_switcher::FABEO_CPABE);
    measure_runtimes(id, S, kpabbe_V, kpabbe_Z, kpabbe_J, kpabbe_Vprime, kpabbe_Zprime, precision, repetitions, kpabbe_switcher::KPABBE);
    measure_runtimes(id, S, kpabbe_V, kpabbe_Z, kpabbe_J, kpabbe_Vprime, kpabbe_Zprime, precision, repetitions, kpabbe_switcher::KPABBE_S);
    measure_runtimes(id, S, cpabbe_J, cpabbe_V, cpabbe_Z, cpabbe_Vprime, cpabbe_Zprime, precision, repetitions, cpabbe_switcher::CPABBE);
    measure_runtimes(id, S, cpabbe_J, cpabbe_V, cpabbe_Z, cpabbe_Vprime, cpabbe_Zprime, precision, repetitions, cpabbe_switcher::CPABBE_S);
    //*/

    // Measure byte lengths of RELIC ABE Schemes
    /*
    std::cout << "ABE RELIC Byte Lengths:" << std::endl;
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FIBE);
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FIBE_S);
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FIBE_LARGE);
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FIBE_LARGE_S);
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::KPABE);
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::KPABE_S);
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::KPABE_LARGE);
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::KPABE_LARGE_S);
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FAME_KPABE);
    measure_byte_lengths<uint16_t, uint16_t>(kpabe_publisher_id, kpabe_recipient_policy, kpabe_switcher::FABEO_KPABE);
    measure_byte_lengths<uint16_t, uint16_t>(cpabe_publisher_policy, cpabe_recipient_id, cpabe_switcher::CPABE);
    measure_byte_lengths<uint16_t, uint16_t>(cpabe_publisher_policy, cpabe_recipient_id, cpabe_switcher::CPABE_S);
    measure_byte_lengths<uint16_t, uint16_t>(cpabe_publisher_policy, cpabe_recipient_id, cpabe_switcher::FAME_CPABE);
    measure_byte_lengths<uint16_t, uint16_t>(cpabe_publisher_policy, cpabe_recipient_id, cpabe_switcher::FABEO_CPABE);
    measure_byte_lengths<uint16_t>(id, S, kpabbe_V, kpabbe_Z, kpabbe_J, kpabbe_Vprime, kpabbe_Zprime, kpabbe_switcher::KPABBE);
    measure_byte_lengths<uint16_t>(id, S, kpabbe_V, kpabbe_Z, kpabbe_J, kpabbe_Vprime, kpabbe_Zprime, kpabbe_switcher::KPABBE_S);
    measure_byte_lengths<uint16_t>(id, S, cpabbe_J, cpabbe_V, cpabbe_Z, cpabbe_Vprime, cpabbe_Zprime, cpabbe_switcher::CPABBE);
    measure_byte_lengths<uint16_t>(id, S, cpabbe_J, cpabbe_V, cpabbe_Z, cpabbe_Vprime, cpabbe_Zprime, cpabbe_switcher::CPABBE_S);
    //*/

    // Test Reference SGC Schemes
    /*
    std::cout << "SGC Tests:" << std::endl;
    skdc_test(group_size);
    lkh_test(group_size, degree, false, false);
    lkh_test(group_size, degree, false, true);
    s2rp_test(group_size, degree, false);
    //*/


    // Run Reference SGC Schemes
    /*
    std::cout << "Reference SGC Runs:" << std::endl;
    switch (action) {
        case RUN_GC:
            skdc_run_gc(group_size, precision, repetitions);
            lkh_run_gc(group_size, degree, precision, repetitions, false);
            lkh_run_gc(group_size, degree, precision, repetitions, true);
            s2rp_run_gc(group_size, degree, chain_length, precision, repetitions);
            break;
        case RUN_GM: {
            std::vector<unsigned char> join_ind_key = load_bytes_from_file("join_ind_key");
            skdc_run_gm("skdc_msgs", join_ind_key, precision, repetitions);
            lkh_run_gm("lkh_uor_msgs", join_ind_key, precision, repetitions, false);
            lkh_run_gm("lkh_kor_msgs", join_ind_key, precision, repetitions, true);
            s2rp_run_gm("s2rp_msgs", join_ind_key, precision, repetitions);
            join_ind_key.clear();
            break;
        }
        case SAVE_MESSAGES: {
            const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
            save_bytes_to_file(join_ind_key, "join_ind_key");
            skdc_generate_messages("skdc_msgs", join_ind_key, group_size, repetitions);
            lkh_generate_messages("lkh_uor_msgs", join_ind_key, group_size, degree, repetitions, false);
            lkh_generate_messages("lkh_kor_msgs", join_ind_key, group_size, degree, repetitions, true);
            s2rp_generate_messages("s2rp_msgs", join_ind_key, group_size, degree, chain_length, repetitions);
            break;
        }
        case MEASURE_MSG_SIZES:
            skdc_measure_byte_lengths(group_size);
            lkh_measure_byte_lengths(group_size, degree, false);
            lkh_measure_byte_lengths(group_size, degree, true);
            s2rp_measure_byte_lengths(group_size, degree, chain_length);
            break;
    }
    //*/

    // Test ABE SGC Schemes
    /*
    std::cout << "ABE SGC Tests:" << std::endl;
    naive_kpabe_test(group_size, kpabe_switcher::FIBE);
    naive_kpabe_test(group_size, kpabe_switcher::FIBE_S);
    naive_kpabe_test(group_size, kpabe_switcher::FIBE_LARGE);
    naive_kpabe_test(group_size, kpabe_switcher::FIBE_LARGE_S);
    naive_kpabe_test(group_size, kpabe_switcher::KPABE);
    naive_kpabe_test(group_size, kpabe_switcher::KPABE_S);
    naive_kpabe_test(group_size, kpabe_switcher::KPABE_LARGE);
    naive_kpabe_test(group_size, kpabe_switcher::KPABE_LARGE_S);
    naive_kpabe_test(group_size, kpabe_switcher::FAME_KPABE);
    naive_kpabe_test(group_size, kpabe_switcher::FABEO_KPABE);
    naive_cpabe_test(group_size, cpabe_switcher::CPABE);
    naive_cpabe_test(group_size, cpabe_switcher::CPABE_S);
    naive_cpabe_test(group_size, cpabe_switcher::FAME_CPABE);
    naive_cpabe_test(group_size, cpabe_switcher::FABEO_CPABE);
    flat_table_test(group_size, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE);
    flat_table_test(group_size, ESPRESSO, cpabe_switcher::CPABE);
    flat_table_test(group_size, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE_S);
    flat_table_test(group_size, ESPRESSO, cpabe_switcher::CPABE_S);
    flat_table_test(group_size, QUINE_MC_CLUSKEY, cpabe_switcher::FABEO_CPABE);
    flat_table_test(group_size, ESPRESSO, cpabe_switcher::FABEO_CPABE);
    kpabbe_sgc_test(group_size, kpabbe_switcher::KPABBE);
    kpabbe_sgc_test(group_size, kpabbe_switcher::KPABBE_S);
    cpabbe_sgc_test(group_size, cpabbe_switcher::CPABBE);
    cpabbe_sgc_test(group_size, cpabbe_switcher::CPABBE_S);
    //*/

    // Run SGC ABE Schemes
    /*
    std::cout << "SGC ABE Runs:" << std::endl;
    switch (action) {
        case RUN_GC:
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::FIBE);
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::FIBE_S);
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::FIBE_LARGE);
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::FIBE_LARGE_S);
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::KPABE);
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::KPABE_S);
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::KPABE_LARGE);
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::KPABE_LARGE_S);
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::FAME_KPABE);
            naive_kpabe_run_gc(group_size, precision, repetitions, kpabe_switcher::FABEO_KPABE);
            naive_cpabe_run_gc(group_size, precision, repetitions, cpabe_switcher::CPABE);
            naive_cpabe_run_gc(group_size, precision, repetitions, cpabe_switcher::CPABE_S);
            naive_cpabe_run_gc(group_size, precision, repetitions, cpabe_switcher::FAME_CPABE);
            naive_cpabe_run_gc(group_size, precision, repetitions, cpabe_switcher::FABEO_CPABE);

            flat_table_run_gc(group_size, precision, repetitions, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE);
            flat_table_run_gc(group_size, precision, repetitions, ESPRESSO, cpabe_switcher::CPABE);
            flat_table_run_gc(group_size, precision, repetitions, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE_S);
            flat_table_run_gc(group_size, precision, repetitions, ESPRESSO, cpabe_switcher::CPABE_S);
            flat_table_run_gc(group_size, precision, repetitions, QUINE_MC_CLUSKEY, cpabe_switcher::FABEO_CPABE);
            flat_table_run_gc(group_size, precision, repetitions, ESPRESSO, cpabe_switcher::FABEO_CPABE);

            kpabbe_sgc_run_gc(group_size, precision, repetitions, kpabbe_switcher::KPABBE);
            kpabbe_sgc_run_gc(group_size, precision, repetitions, kpabbe_switcher::KPABBE_S);
            cpabbe_sgc_run_gc(group_size, precision, repetitions, cpabbe_switcher::CPABBE);
            cpabbe_sgc_run_gc(group_size, precision, repetitions, cpabbe_switcher::CPABBE_S);

            break;
        case RUN_GM: {
            std::vector<unsigned char> join_ind_key = load_bytes_from_file("join_ind_key");
            naive_kpabe_run_gm("naive_fibe_msgs", join_ind_key, precision, repetitions, kpabe_switcher::FIBE);
            naive_kpabe_run_gm("naive_fibe_s_msgs", join_ind_key, precision, repetitions, kpabe_switcher::FIBE_S);
            naive_kpabe_run_gm("naive_fibe_large_msgs", join_ind_key, precision, repetitions, kpabe_switcher::FIBE_LARGE);
            naive_kpabe_run_gm("naive_fibe_large_s_msgs", join_ind_key, precision, repetitions, kpabe_switcher::FIBE_LARGE_S);
            naive_kpabe_run_gm("naive_kpabe_msgs", join_ind_key, precision, repetitions, kpabe_switcher::KPABE);
            naive_kpabe_run_gm("naive_kpabe_s_msgs", join_ind_key, precision, repetitions, kpabe_switcher::KPABE_S);
            naive_kpabe_run_gm("naive_kpabe_large_msgs", join_ind_key, precision, repetitions, kpabe_switcher::KPABE_LARGE);
            naive_kpabe_run_gm("naive_kpabe_large_s_msgs", join_ind_key, precision, repetitions, kpabe_switcher::KPABE_LARGE_S);
            naive_kpabe_run_gm("naive_famekpabe_msgs", join_ind_key, precision, repetitions, kpabe_switcher::FAME_KPABE);
            naive_kpabe_run_gm("naive_fabeokpabe_msgs", join_ind_key, precision, repetitions, kpabe_switcher::FABEO_KPABE);
            naive_cpabe_run_gm("naive_cpabe_msgs", join_ind_key, precision, repetitions, cpabe_switcher::CPABE);
            naive_cpabe_run_gm("naive_cpabe_s_msgs", join_ind_key, precision, repetitions, cpabe_switcher::CPABE_S);
            naive_cpabe_run_gm("naive_famecpabe_msgs", join_ind_key, precision, repetitions, cpabe_switcher::FAME_CPABE);
            naive_cpabe_run_gm("naive_fabeocpabe_msgs", join_ind_key, precision, repetitions, cpabe_switcher::FABEO_CPABE);
            flat_table_run_gm("ft_q_cpabe_msgs", join_ind_key, precision, repetitions, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE);
            flat_table_run_gm("ft_e_cpabe_msgs", join_ind_key, precision, repetitions, ESPRESSO, cpabe_switcher::CPABE);
            flat_table_run_gm("ft_q_cpabe_s_msgs", join_ind_key, precision, repetitions, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE_S);
            flat_table_run_gm("ft_e_cpabe_s_msgs", join_ind_key, precision, repetitions, ESPRESSO, cpabe_switcher::CPABE_S);
            flat_table_run_gm("ft_q_fabeocpabe_msgs", join_ind_key, precision, repetitions, QUINE_MC_CLUSKEY, cpabe_switcher::FABEO_CPABE);
            flat_table_run_gm("ft_e_fabeocpabe_msgs", join_ind_key, precision, repetitions, ESPRESSO, cpabe_switcher::FABEO_CPABE);
            kpabbe_sgc_run_gm("kpabbe_sgc_msgs", join_ind_key, precision, repetitions, kpabbe_switcher::KPABBE);
            kpabbe_sgc_run_gm("kpabbe_sgc_s_msgs", join_ind_key, precision, repetitions, kpabbe_switcher::KPABBE_S);
            cpabbe_sgc_run_gm("cpabbe_sgc_msgs", join_ind_key, precision, repetitions, cpabbe_switcher::CPABBE);
            cpabbe_sgc_run_gm("cpabbe_sgc_s_msgs", join_ind_key, precision, repetitions, cpabbe_switcher::CPABBE_S);
            join_ind_key.clear();
            break;
        }
        case SAVE_MESSAGES: {
            const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
            save_bytes_to_file(join_ind_key, "join_ind_key");

            naive_kpabe_generate_messages("naive_fibe_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::FIBE);
            naive_kpabe_generate_messages("naive_fibe_s_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::FIBE_S);
            naive_kpabe_generate_messages("naive_fibe_large_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::FIBE_LARGE);
            naive_kpabe_generate_messages("naive_fibe_large_s_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::FIBE_LARGE_S);
            naive_kpabe_generate_messages("naive_kpabe_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::KPABE);
            naive_kpabe_generate_messages("naive_kpabe_s_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::KPABE_S);
            naive_kpabe_generate_messages("naive_kpabe_large_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::KPABE_LARGE);
            naive_kpabe_generate_messages("naive_kpabe_large_s_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::KPABE_LARGE_S);
            naive_kpabe_generate_messages("naive_famekpabe_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::FAME_KPABE);
            naive_kpabe_generate_messages("naive_fabeokpabe_msgs", join_ind_key, group_size, repetitions, kpabe_switcher::FABEO_KPABE);
            naive_cpabe_generate_messages("naive_cpabe_msgs", join_ind_key, group_size, repetitions, cpabe_switcher::CPABE);
            naive_cpabe_generate_messages("naive_cpabe_s_msgs", join_ind_key, group_size, repetitions, cpabe_switcher::CPABE_S);
            naive_cpabe_generate_messages("naive_famecpabe_msgs", join_ind_key, group_size, repetitions, cpabe_switcher::FAME_CPABE);
            naive_cpabe_generate_messages("naive_fabeocpabe_msgs", join_ind_key, group_size, repetitions, cpabe_switcher::FABEO_CPABE);
            flat_table_generate_messages("ft_q_cpabe_msgs", join_ind_key, group_size, repetitions, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE);
            flat_table_generate_messages("ft_e_cpabe_msgs", join_ind_key, group_size, repetitions, ESPRESSO, cpabe_switcher::CPABE);
            flat_table_generate_messages("ft_q_cpabe_s_msgs", join_ind_key, group_size, repetitions, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE_S);
            flat_table_generate_messages("ft_e_cpabe_s_msgs", join_ind_key, group_size, repetitions, ESPRESSO, cpabe_switcher::CPABE_S);
            flat_table_generate_messages("ft_q_fabeocpabe_msgs", join_ind_key, group_size, repetitions, QUINE_MC_CLUSKEY, cpabe_switcher::FABEO_CPABE);
            flat_table_generate_messages("ft_e_fabeocpabe_msgs", join_ind_key, group_size, repetitions, ESPRESSO, cpabe_switcher::FABEO_CPABE);
            kpabbe_sgc_generate_messages("kpabbe_sgc_msgs", join_ind_key, group_size, repetitions, kpabbe_switcher::KPABBE);
            kpabbe_sgc_generate_messages("kpabbe_sgc_s_msgs", join_ind_key, group_size, repetitions, kpabbe_switcher::KPABBE_S);
            cpabbe_sgc_generate_messages("cpabbe_sgc_msgs", join_ind_key, group_size, repetitions, cpabbe_switcher::CPABBE);
            cpabbe_sgc_generate_messages("cpabbe_sgc_s_msgs", join_ind_key, group_size, repetitions, cpabbe_switcher::CPABBE_S);

            break;
        }
        case MEASURE_MSG_SIZES:
            naive_kpabe_measure_byte_lengths(group_size, kpabe_switcher::FIBE);
            naive_kpabe_measure_byte_lengths(group_size, kpabe_switcher::FIBE_S);
            naive_kpabe_measure_byte_lengths(group_size, kpabe_switcher::KPABE);
            naive_kpabe_measure_byte_lengths(group_size, kpabe_switcher::KPABE_S);
            naive_kpabe_measure_byte_lengths(group_size, kpabe_switcher::FAME_KPABE);
            naive_kpabe_measure_byte_lengths(group_size, kpabe_switcher::FABEO_KPABE);
            naive_cpabe_measure_byte_lengths(group_size, cpabe_switcher::CPABE);
            naive_cpabe_measure_byte_lengths(group_size, cpabe_switcher::CPABE_S);
            naive_cpabe_measure_byte_lengths(group_size, cpabe_switcher::FAME_CPABE);
            naive_cpabe_measure_byte_lengths(group_size, cpabe_switcher::FABEO_CPABE);
            flat_table_measure_byte_lengths(group_size, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE);
            flat_table_measure_byte_lengths(group_size, ESPRESSO, cpabe_switcher::CPABE);
            flat_table_measure_byte_lengths(group_size, QUINE_MC_CLUSKEY, cpabe_switcher::CPABE_S);
            flat_table_measure_byte_lengths(group_size, ESPRESSO, cpabe_switcher::CPABE_S);
            flat_table_measure_byte_lengths(group_size, QUINE_MC_CLUSKEY, cpabe_switcher::FABEO_CPABE);
            flat_table_measure_byte_lengths(group_size, ESPRESSO, cpabe_switcher::FABEO_CPABE);
            kpabbe_sgc_measure_byte_lengths(group_size, kpabbe_switcher::KPABBE);
            kpabbe_sgc_measure_byte_lengths(group_size, kpabbe_switcher::KPABBE_S);
            cpabbe_sgc_measure_byte_lengths(group_size, cpabbe_switcher::CPABBE);
            cpabbe_sgc_measure_byte_lengths(group_size, cpabbe_switcher::CPABBE_S);
            break;
    }
    //*/

    // Cleanup
    delete kpabe_recipient_policy;
    delete cpabe_publisher_policy;
    core_clean();
}
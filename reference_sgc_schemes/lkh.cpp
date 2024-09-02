#include <chrono>
#include <vector>
#include <map>
#include <cstring>
#include <iostream>
#include <iomanip>
#include "../config.h"
#include "../KeyTree.h"
#include "../random.h"
#include "../serialize.h"
#include "../crypto_functions/aes.h"

#if MASTER_DEVICE == MASTER_PC
#include <random>
#elif MASTER_DEVICE == MASTER_ESP32
#include "esp_random.h"
#endif

// Wong et al. - Secure group communication using key graphs - 2000

using ID_TYPE = uint16_t;

constexpr int byte_length = 16;

struct lkh_gc_state {
    KeyTree *key_tree{};
};

struct lkh_gm_state {
    std::vector<unsigned char> individual_key{};
    ID_TYPE group_size{};
    // Subgroups are indexed with their size => unique for a single user
    std::map<ID_TYPE, std::vector<unsigned char>> group_keys;
};

struct lkh_message {
    std::set<ID_TYPE> receivers;
    std::vector<unsigned char> data{};
};

std::vector<unsigned char> lkh_choose_key(const lkh_gm_state& gm_state, const ID_TYPE key_num) {
    std::vector<unsigned char> key;
    if (key_num == 1) {
        key = gm_state.individual_key;
    } else {
        key = gm_state.group_keys.at(key_num);
    }
    return key;
}

std::vector<unsigned char> lkh_get_communication_key(const lkh_gm_state& gm_state) {
    return gm_state.group_keys.at(gm_state.group_size);
}

// No KOR version: UOR is just better for initialization
std::vector<lkh_message> lkh_initialize_gc(const lkh_gc_state& gc_state) {
    KeyTree *kt = gc_state.key_tree;
    const std::set<int> members = kt->get_group_members();
    const int num_members = members.size();
    std::map<ID_TYPE, ID_TYPE> member_to_text;
    std::vector<std::vector<unsigned char>> length_and_keynum_texts(num_members);
    std::vector<std::vector<unsigned char>> plaintexts(num_members);
    int counter = 0;
    for (const auto i : members) {
        length_and_keynum_texts.at(counter).push_back('i');
        length_and_keynum_texts.at(counter).push_back(0);
        // Indicates with which key the message is encrypted (subgroup size)
        serialize_int<ID_TYPE>(length_and_keynum_texts.at(counter), 1);
        member_to_text[i] = counter++;
    }
    for (const auto i : kt->get_all_positions()) {
        std::set<int> subgroup_members = kt->get_members(i);
        const ID_TYPE key_num = subgroup_members.size();
        if (key_num > 1) {
            std::vector<unsigned char> pos_data = kt->get_key(i);
            for (const auto j :subgroup_members) {
                const int text_num = member_to_text.at(j);
                std::vector<unsigned char>& length_and_keynum_text = length_and_keynum_texts[text_num];
                std::vector<unsigned char>& plaintext = plaintexts.at(text_num);
                serialize_int<ID_TYPE>(length_and_keynum_text, key_num);
                plaintext.insert(plaintext.end(), pos_data.begin(), pos_data.end());
                ++length_and_keynum_text.at(1);
            }
        }
    }
    std::vector<lkh_message> messages;
    for (const auto i : members) {
        const int text_num = member_to_text.at(i);
        std::vector<unsigned char>& new_member_message = length_and_keynum_texts.at(text_num);
        std::vector<unsigned char> ciphertext = aes_encrypt(kt->get_key(kt->get_member_position(i)), plaintexts[text_num]);
        new_member_message.insert(new_member_message.end(), ciphertext.begin(), ciphertext.end());
        messages.push_back({std::set{static_cast<ID_TYPE>(i)}, new_member_message});
    }
    return messages;
}

std::vector<lkh_message> lkh_join_uor_gc(const lkh_gc_state& gc_state, const ID_TYPE member_id, const std::vector<unsigned char>& individual_key) {
    KeyTree *kt = gc_state.key_tree;
    keytree_update_data update_data = kt->insert_member(member_id, individual_key);
    const std::vector<std::vector<unsigned char>>& key_vec = update_data.key_vec;
    const auto data_vec = std::vector<std::pair<ID_TYPE, std::vector<unsigned char>>>(update_data.data_vec.begin(), update_data.data_vec.end());
    auto& member_vec = update_data.member_vec;

    const uint8_t vec_size = key_vec.size();
    std::vector<lkh_message> result;
    result.reserve(vec_size + 1);
    std::vector new_member_message{'j', vec_size};
    // Indicates with which key the message is encrypted (subgroup size)
    serialize_int<ID_TYPE>(new_member_message, 1);
    std::vector<unsigned char> plaintext;

    // Ordering is important for the user not to override its own values
    for (auto it = data_vec.crbegin(); it != data_vec.crend(); ++it) {
        const auto [key_num, bytes] = *it;
        serialize_int<ID_TYPE>(new_member_message, key_num);
        plaintext.insert(plaintext.end(), bytes.begin(), bytes.end());
    }
    std::vector<unsigned char> ciphertext = aes_encrypt(individual_key, plaintext);
    new_member_message.insert(new_member_message.end(), ciphertext.begin(), ciphertext.end());
    result.push_back({std::set{member_id}, new_member_message});


    for (int i = vec_size - 1; i >= 0; --i) {
        const int key_num = member_vec.at(i).size();
        if (i > 0) {
            for (const auto x : member_vec.at(i-1)) {
                member_vec.at(i).erase(x);
            }
        }
        const uint8_t length = vec_size - i;
        std::vector old_member_message{'j', length};
        serialize_int<ID_TYPE>(old_member_message, key_num);
        std::vector<unsigned char> plaintext2;
        // Ordering is important for the user not to override its own values
        for (const auto& [key_num, bytes]: std::vector(data_vec.crbegin(), data_vec.crend() - i)) {
            serialize_int<ID_TYPE>(old_member_message, key_num);
            plaintext2.insert(plaintext2.end(), bytes.begin(), bytes.end());
        }
        std::vector<unsigned char> ciphertext2 = aes_encrypt(key_vec.at(i), plaintext2);
        old_member_message.insert(old_member_message.end(), ciphertext2.begin(), ciphertext2.end());
        result.push_back({std::set<ID_TYPE>{member_vec.at(i).begin(), member_vec.at(i).end()}, old_member_message});
    }
    return result;
}

std::vector<lkh_message> lkh_join_kor_gc(const lkh_gc_state& gc_state, const ID_TYPE member_id, const std::vector<unsigned char>& individual_key) {
    KeyTree *kt = gc_state.key_tree;
    keytree_update_data update_data = kt->insert_member(member_id, individual_key);
    const std::vector<std::vector<unsigned char>>& key_vec = update_data.key_vec;
    const auto data_vec = std::vector<std::pair<ID_TYPE, std::vector<unsigned char>>>(update_data.data_vec.begin(), update_data.data_vec.end());
    const auto& member_vec = update_data.member_vec;

    const uint8_t vec_size = key_vec.size();
    std::vector<lkh_message> result;
    result.reserve(vec_size + 1);

    std::vector new_member_message{'j', vec_size};
    // Indicates with which key the message is encrypted (subgroup size)
    serialize_int<ID_TYPE>(new_member_message, 1);
    std::vector<unsigned char> plaintext;

    // Ordering is important for the user not to override its own values
    for (auto it = data_vec.crbegin(); it != data_vec.crend(); ++it) {
        const auto& [key_num, bytes] = *it;
        serialize_int<ID_TYPE>(new_member_message, key_num);
        plaintext.insert(plaintext.end(), bytes.begin(), bytes.end());
    }

    std::vector<unsigned char> ciphertext = aes_encrypt(individual_key, plaintext);
    new_member_message.insert(new_member_message.end(), ciphertext.begin(), ciphertext.end());
    result.push_back({std::set{member_id}, new_member_message});

    // Ordering is important for the user not to override its own values
    for (int i = vec_size - 1; i >= 0; --i) {
        std::vector<unsigned char> old_member_message{'j', 1};
        serialize_int<ID_TYPE>(old_member_message, member_vec.at(i).size());
        serialize_int<ID_TYPE>(old_member_message, data_vec.at(i).first);
        std::vector<unsigned char> ciphertext2 = aes_encrypt(key_vec.at(i), data_vec.at(i).second);
        old_member_message.insert(old_member_message.end(), ciphertext2.begin(), ciphertext2.end());
        result.push_back({std::set<ID_TYPE>{member_vec.at(i).begin(), member_vec.at(i).end()}, old_member_message});
    }
    return result;
}

void lkh_join_gm(lkh_gm_state& gm_state, const std::vector<unsigned char>& message) {
    int offset = 0;
    const uint8_t length = message.at(offset++);
    const auto decryption_key_num = deserialize_int<ID_TYPE>(message, &offset);
    std::vector<ID_TYPE> key_nums(length);
    for (int i = 0; i < length; ++i) {
        key_nums[i] = deserialize_int<ID_TYPE>(message, &offset);
    }
    const std::vector<unsigned char> decryption_key = lkh_choose_key(gm_state, decryption_key_num);
    const std::vector<unsigned char> plaintext = aes_decrypt(decryption_key, std::vector(message.begin() + offset, message.end()));
    for (int i = 0; i < length; ++i) {
        const ID_TYPE key_num = key_nums.at(i);
        // Delete the old version of the (sub-)group key (works because top down)
        gm_state.group_keys.erase(key_num - 1);
        // Set the new (sub-)group key
        gm_state.group_keys[key_num] = std::vector(plaintext.begin() + i * byte_length, plaintext.begin() + (i + 1) * byte_length);
        if (key_num > gm_state.group_size) {
            gm_state.group_size = key_num;
        }
    }
}

std::vector<lkh_message> lkh_leave_uor_gc(const lkh_gc_state& gc_state, const ID_TYPE member_id) {
    KeyTree *kt = gc_state.key_tree;
    const keytree_update_data update_data = kt->remove_member(member_id);
    const std::vector<std::vector<unsigned char>>& key_vec = update_data.key_vec;
    const auto data_vec = std::vector<std::pair<ID_TYPE, std::vector<unsigned char>>>(update_data.data_vec.begin(), update_data.data_vec.end());
    const auto& member_vec = update_data.member_vec;
    const std::vector<int>& children_vec = update_data.children_vec;
    const bool gk_delete = update_data.gk_delete;

    const int children_vec_size = children_vec.size();
    if (children_vec_size == 0) {
        std::set<int> members = kt->get_group_members();
        return std::vector<lkh_message>{{std::set<ID_TYPE>(members.begin(), members.end()),
                                                std::vector<unsigned char>{'x'}}};
    }
    std::vector<lkh_message> result;
    int k = 0;
    // Ordering is important for the user not to override its own values
    for (int i = 0; i < children_vec_size; ++i) {
        for (int j = 0; j < children_vec.at(i); ++j) {
            // The first sibling is the node itself
            if (j != 0 || i == 0) {
                unsigned char symbol;
                if (gk_delete && i == 0 && j == 0) {
                    symbol = 'L';
                } else {
                    symbol = 'l';
                }
                const uint8_t length = data_vec.size() - i;
                std::vector<unsigned char> message{symbol, length};
                serialize_int<ID_TYPE>(message, member_vec.at(k).size());
                std::vector<unsigned char> plaintext;
                for (const auto& [key_num, bytes]: std::vector(data_vec.cbegin() + i, data_vec.cend())) {
                    serialize_int<ID_TYPE>(message, key_num);
                    plaintext.insert(plaintext.end(), bytes.begin(), bytes.end());
                }
                std::vector<unsigned char> ciphertext = aes_encrypt(key_vec.at(k), plaintext);
                message.insert(message.end(), ciphertext.begin(), ciphertext.end());
                result.push_back({std::set<ID_TYPE>{member_vec.at(k).begin(), member_vec.at(k).end()}, message});
            }
            ++k;
        }
    }
    return result;
}

std::vector<lkh_message> lkh_leave_kor_gc(const lkh_gc_state& gc_state, const int member_id) {
    KeyTree *kt = gc_state.key_tree;
    const keytree_update_data update_data = kt->remove_member(member_id);
    const std::vector<std::vector<unsigned char>>& key_vec = update_data.key_vec;
    const auto data_vec = std::vector<std::pair<ID_TYPE, std::vector<unsigned char>>>(update_data.data_vec.begin(), update_data.data_vec.end());
    const auto& member_vec = update_data.member_vec;
    const std::vector<int>& children_vec = update_data.children_vec;
    const bool gk_delete = update_data.gk_delete;

    const int vec_size = key_vec.size();
    const int children_vec_size = children_vec.size();
    if (children_vec_size == 0) {
        std::set<int> members = kt->get_group_members();
        return std::vector<lkh_message>{{std::set<ID_TYPE>(members.begin(), members.end()),
                                                std::vector<unsigned char>{'x'}}};
    }
    std::vector<lkh_message> result(vec_size);
    int k = 0;
    // Ordering is important for the user not to override its own values
    for (int i = 0; i < children_vec_size; ++i) {
        for (int j = 0; j < children_vec.at(i); ++j) {
            unsigned char symbol;
            if (gk_delete && i == 0 && j == 0) {
                symbol = 'L';
            } else {
                symbol = 'l';
            }
            std::vector<unsigned char> message{symbol, 1};
            serialize_int<ID_TYPE>(message, member_vec.at(k).size());
            serialize_int<ID_TYPE>(message, data_vec.at(i).first);
            std::vector<unsigned char> ciphertext = aes_encrypt(key_vec.at(k), data_vec.at(i).second);
            message.insert(message.end(), ciphertext.begin(), ciphertext.end());
            result[k] = {std::set<ID_TYPE>{member_vec.at(k).begin(), member_vec.at(k).end()}, message};
            ++k;
        }
    }
    return result;
}

void lkh_leave_gm(lkh_gm_state& gm_state, const std::vector<unsigned char>& message, const bool gk_delete) {
    int offset = 0;
    const uint8_t length = message.at(offset++);
    const auto decryption_key_num = deserialize_int<ID_TYPE>(message, &offset);
    std::vector<ID_TYPE> key_nums(length);
    for (int i = 0; i < length; ++i) {
        key_nums[i] = deserialize_int<ID_TYPE>(message, &offset);
    }
    const std::vector<unsigned char> decryption_key = lkh_choose_key(gm_state, decryption_key_num);
    const std::vector<unsigned char> plaintext = aes_decrypt(decryption_key, std::vector(message.begin() + offset, message.end()));
    if (gk_delete) {
        const auto it = --gm_state.group_keys.find(key_nums.at(0) + 1);
        gm_state.group_keys.erase(it);
    }
    for (int i = 0; i < length; ++i) {
        const ID_TYPE key_num = key_nums.at(i);
        // Delete the old version of the (sub-)group key (works because bottom up)
        gm_state.group_keys.erase(key_num + 1);
        // Set the new (sub-)group key
        gm_state.group_keys[key_num] = std::vector(plaintext.begin() + i * byte_length, plaintext.begin() + (i + 1) * byte_length);
        if (key_num == gm_state.group_size - 1) {
            --gm_state.group_size;
        }
    }
}

void lkh_update_gm(lkh_gm_state& gm_state, const std::vector<unsigned char>& ciphertext) {
    const unsigned char action = ciphertext.at(0);
    const auto rest = std::vector(ciphertext.begin() + 1, ciphertext.end());
    if (action == 'i' || action == 'x') {
        gm_state.group_keys.clear();
        gm_state.group_size = 1;
    }
    if (action == 'i' || action == 'j') {
        lkh_join_gm(gm_state, rest);
    } else if (action == 'l' || action == 'L') {
        const bool gk_delete = action == 'L';
        lkh_leave_gm(gm_state, rest, gk_delete);
    }
}

void lkh_test(const int size, const int degree, const bool print_tree, const int use_kor) {
    const int join_user = size + 1;
    constexpr int leave_user = 1;
    const std::string rekeying_string = use_kor ? "KOR" : "UOR";
    std::vector<std::pair<int, std::vector<unsigned char>>> individual_keys(size);
    for (int i = 0; i < size; ++i) {
        individual_keys[i] = {i+1, byte_vector_random(byte_length)};
    }
    KeyTree *kt = KeyTree::create_tree_graph(byte_length, degree, individual_keys, 1);
    const lkh_gc_state gc_state{kt};
    std::map<int, lkh_gm_state> gm_states;
    for (const auto& [user, individual_key] : individual_keys) {
        gm_states[user] = lkh_gm_state{
            individual_key, 1, std::map<ID_TYPE, std::vector<unsigned char>>()
        };
    }

    // Initialization
    const std::vector<lkh_message> init_messages = lkh_initialize_gc(gc_state);
    if (print_tree) {
        kt->print();
    }
    for (const auto& [receivers, message] : init_messages) {
        for (const auto receiver : receivers) {
            lkh_update_gm(gm_states.at(receiver), message);
        }
    }

    // Join Values Initialization
    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
    gm_states[join_user] = lkh_gm_state{join_ind_key};

    // Join
    std::vector<lkh_message> join_messages;
    if (use_kor) {
        join_messages = lkh_join_kor_gc(gc_state, join_user, join_ind_key);
    } else {
        join_messages = lkh_join_uor_gc(gc_state, join_user, join_ind_key);
    }
    if (print_tree) {
        kt->print();
    }

    for (const auto& [receivers, message] : join_messages) {
        for (const auto receiver : receivers) {
            lkh_update_gm(gm_states.at(receiver), message);
        }
    }

    // Leave
    std::vector<lkh_message> leave_messages;
    if (use_kor) {
        leave_messages = lkh_leave_kor_gc(gc_state, leave_user);
    } else {
        leave_messages = lkh_leave_uor_gc(gc_state, leave_user);
    }
    if (print_tree) {
        kt->print();
    }

    for (const auto& [receivers, message] : leave_messages) {
        for (const auto receiver : receivers) {
            lkh_update_gm(gm_states.at(receiver), message);
        }
    }

    const std::vector<unsigned char> server_communication_key = kt->get_group_key();
    const std::set<int> group_members = kt->get_group_members();
    for (const auto& [user, state] : gm_states) {
        if (group_members.contains(user)) {
            if (std::memcmp(server_communication_key.data(), lkh_get_communication_key(state).data(), byte_length) != 0) {
                std::cerr << "LKH (" << rekeying_string << "): The communication key of user " << user << " does not match the server communication key";
                exit(-1);
            }
        }
    }
    std::cout << "LKH (" << rekeying_string << "): The server communication key matches all user communication keys" << std::endl;

    // Cleanup
    delete gc_state.key_tree;
}

void lkh_run_gc(const int size, const int degree, const int precision, const int repetitions, const int use_kor) {
    std::chrono::steady_clock::time_point begin;
    std::chrono::steady_clock::time_point end;
    const std::string rekeying_string = use_kor ? "KOR" : "UOR";
    std::vector<std::pair<int, std::vector<unsigned char>>> individual_keys(size);
    for (int i = 0; i < size; ++i) {
        individual_keys[i] = {i+1, byte_vector_random(byte_length)};
    }
    KeyTree *kt = KeyTree::create_tree_graph(byte_length, degree, individual_keys, 1);
    const lkh_gc_state gc_state{kt};

    long gc_join_times[repetitions];
    long gc_leave_times[repetitions];

    for (int i = 0; i < repetitions; ++i) {
        // Join
        const int join_user = size + 1;
        const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
        begin = std::chrono::steady_clock::now();
        if (use_kor) {
            lkh_join_kor_gc(gc_state, join_user, join_ind_key);
        } else {
            lkh_join_uor_gc(gc_state, join_user, join_ind_key);
        }
        end = std::chrono::steady_clock::now();
        gc_join_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();

        if (use_kor) {
            lkh_leave_kor_gc(gc_state, join_user);
        } else {
            lkh_leave_uor_gc(gc_state, join_user);
        }
    }
    auto [mean, stddev] = calculate_mean_stddev(gc_join_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "LKH (" << rekeying_string << ") GC Join Time: Avg: " << mean << " " << stddev << std::endl;

    // Leave
    const std::set<int> members = gc_state.key_tree->get_group_members();
    for (int i = 0; i < repetitions; ++i) {
        auto leave_it = members.begin();
#if MASTER_DEVICE == MASTER_PC
        std::random_device dev;
        std::mt19937 rng(dev());
        std::uniform_int_distribution<std::mt19937::result_type> dist(0,members.size()-1);
        std::advance(leave_it, dist(rng));
#elif MASTER_DEVICE == MASTER_ESP32
        std::advance(leave_it, esp_random()%members.size());
#endif
        const int leave_user = *leave_it;

        begin = std::chrono::steady_clock::now();
        if (use_kor) {
            lkh_leave_kor_gc(gc_state, leave_user);
        } else {
            lkh_leave_uor_gc(gc_state, leave_user);
        }
        end = std::chrono::steady_clock::now();
        gc_leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();

        const std::vector<unsigned char> leave_join_ind_key = byte_vector_random(byte_length);
        if (use_kor) {
            lkh_join_kor_gc(gc_state, leave_user, leave_join_ind_key);
        } else {
            lkh_join_uor_gc(gc_state, leave_user, leave_join_ind_key);
        }
    }
    auto [mean2, stddev2] = calculate_mean_stddev(gc_leave_times, repetitions);
    std::cout << "%" << "LKH (" << rekeying_string << ") GC Leave Time: " << mean2 << " " << stddev2 << std::endl;

    // Cleanup
    delete gc_state.key_tree;
}

void lkh_generate_messages(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key,
                           const int size, const int degree, const int repetitions, const int use_kor) {
    int message_counter = 0;
    const int user = size + 1;
    std::vector<std::pair<int, std::vector<unsigned char>>> individual_keys(size);
    for (int i = 0; i < size; ++i) {
        individual_keys[i] = {i+1, byte_vector_random(byte_length)};
    }
    KeyTree *kt = KeyTree::create_tree_graph(byte_length, degree, individual_keys, 1);
    const lkh_gc_state gc_state{kt};

    for (int i = 0; i < repetitions; ++i) {
        std::vector<lkh_message> join_messages;
        if (use_kor) {
            join_messages = lkh_join_kor_gc(gc_state, user, join_ind_key);
        } else {
            join_messages = lkh_join_uor_gc(gc_state, user, join_ind_key);
        }
        for (const auto& [receivers, message] : join_messages) {
            if (receivers.contains(user)) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }
        if (i != repetitions - 1) {
            if (use_kor) {
                lkh_leave_kor_gc(gc_state, user);
            } else {
                lkh_leave_uor_gc(gc_state, user);
            }
        }
    }

    std::set<int> members = gc_state.key_tree->get_group_members();
    for (int i = 0; i < repetitions; ++i) {
        int replace_user = user;
        while (replace_user == user) {
            auto replace_it = members.begin();
#if MASTER_DEVICE == MASTER_PC
            std::random_device dev;
            std::mt19937 rng(dev());
            std::uniform_int_distribution<std::mt19937::result_type> dist(0,members.size()-1);
            std::advance(replace_it, dist(rng));
#elif MASTER_DEVICE == MASTER_ESP32
            std::advance(replace_it, esp_random()%members.size());
#endif
            replace_user = *replace_it;
        }

        std::vector<lkh_message> join_leave_messages;
        if (use_kor) {
            join_leave_messages = lkh_leave_kor_gc(gc_state, replace_user);
        } else {
            join_leave_messages = lkh_leave_uor_gc(gc_state, replace_user);
        }
        for (const auto& [receivers, message] : join_leave_messages) {
            if (receivers.contains(user)) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }

        const std::vector<unsigned char> replace_ind_key = byte_vector_random(byte_length);
        std::vector<lkh_message> join_messages;
        if (use_kor) {
            join_messages = lkh_join_kor_gc(gc_state, replace_user, replace_ind_key);
        } else {
            join_messages = lkh_join_uor_gc(gc_state, replace_user, replace_ind_key);
        }
        for (const auto& [receivers, message] : join_messages) {
            if (receivers.contains(user)) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }
    }

    int replace_user = user;
    while (replace_user == user) {
        auto replace_it = members.begin();
#if MASTER_DEVICE == MASTER_PC
        std::random_device dev;
        std::mt19937 rng(dev());
        std::uniform_int_distribution<std::mt19937::result_type> dist(0,members.size()-1);
        std::advance(replace_it, dist(rng));
#elif MASTER_DEVICE == MASTER_ESP32
        std::advance(replace_it, esp_random()%members.size());
#endif
        replace_user = *replace_it;
    }
    std::vector<lkh_message> join_leave_messages;
    if (use_kor) {
        join_leave_messages = lkh_leave_kor_gc(gc_state, replace_user);
    } else {
        join_leave_messages = lkh_leave_uor_gc(gc_state, replace_user);
    }
    for (const auto& [receivers, message] : join_leave_messages) {
        if (receivers.contains(user)) {
            save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
        }
    }
    members.erase(replace_user);

    for (int i = 0; i < repetitions; ++i) {
        int leave_user = user;
        while (leave_user == user) {
            auto leave_it = members.begin();
#if MASTER_DEVICE == MASTER_PC
            std::random_device dev;
            std::mt19937 rng(dev());
            std::uniform_int_distribution<std::mt19937::result_type> dist(0,members.size()-1);
            std::advance(leave_it, dist(rng));
#elif MASTER_DEVICE == MASTER_ESP32
            std::advance(leave_it, esp_random()%members.size());
#endif
            leave_user = *leave_it;
        }

        std::vector<lkh_message> leave_messages;
        if (use_kor) {
            leave_messages = lkh_leave_kor_gc(gc_state, leave_user);
        } else {
            leave_messages = lkh_leave_uor_gc(gc_state, leave_user);
        }
        for (const auto& [receivers, message] : leave_messages) {
            if (receivers.contains(user)) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }

        const std::vector<unsigned char> leave_join_ind_key = byte_vector_random(byte_length);
        std::vector<lkh_message> leave_join_messages;
        if (use_kor) {
            leave_join_messages = lkh_join_kor_gc(gc_state, leave_user, leave_join_ind_key);
        } else {
            leave_join_messages = lkh_join_uor_gc(gc_state, leave_user, leave_join_ind_key);
        }
        for (const auto& [receivers, message] : leave_join_messages) {
            if (receivers.contains(user)) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }
    }

    // Cleanup
    delete gc_state.key_tree;
}

void lkh_run_gm(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key, const int precision,
                const int repetitions, const int use_kor) {
    std::chrono::steady_clock::time_point begin;
    std::chrono::steady_clock::time_point end;
    const std::string rekeying_string = use_kor ? "KOR" : "UOR";

    int message_counter = 0;

    // Initialization
    lkh_gm_state gm_state{};
    gm_state.individual_key = join_ind_key;
    gm_state.group_size = 1;

    long gm_join_new_times[repetitions];

    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        begin = std::chrono::steady_clock::now();
        lkh_update_gm(gm_state, message);
        end = std::chrono::steady_clock::now();
        gm_join_new_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();

        if (i != repetitions - 1) {
            gm_state.group_keys.clear();
            gm_state.group_size = 1;
        }
    }

    auto [mean, stddev] = calculate_mean_stddev(gm_join_new_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "LKH (" << rekeying_string << ") GM Max. Join New Time: " << mean << " " << stddev << std::endl;

    long gm_join_old_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message1 = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        lkh_update_gm(gm_state, message1);
        const std::vector<unsigned char> message2 = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        begin = std::chrono::steady_clock::now();
        lkh_update_gm(gm_state, message2);
        end = std::chrono::steady_clock::now();
        gm_join_old_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }

    auto [mean2, stddev2] = calculate_mean_stddev(gm_join_old_times, repetitions);
    std::cout << "%" << "LKH (" << rekeying_string << ") GM Max. Join Old Time: " << mean2 << " " << stddev2 << std::endl;


    const std::vector<unsigned char> message = load_bytes_from_file(
            file_prefix + std::to_string(message_counter++));
    lkh_update_gm(gm_state, message);

    long gm_leave_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message1 = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        begin = std::chrono::steady_clock::now();
        lkh_update_gm(gm_state, message1);
        end = std::chrono::steady_clock::now();
        gm_leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        const std::vector<unsigned char> message2 = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        lkh_update_gm(gm_state, message2);
    }
    auto [mean3, stddev3] = calculate_mean_stddev(gm_leave_times, repetitions);
    std::cout << "%" << "LKH (" << rekeying_string << ") GM Max. Leave Time: " << mean3 << " " << stddev3 << std::endl;
}

void lkh_measure_byte_lengths(const int size, const int degree, const int use_kor) {
    const int join_user = size + 1;
    const int leave_user = size;
    const std::string rekeying_string = use_kor ? "KOR" : "UOR";
    std::vector<std::pair<int, std::vector<unsigned char>>> individual_keys(size);
    for (int i = 0; i < size; ++i) {
        individual_keys[i] = {i+1, byte_vector_random(byte_length)};
    }
    KeyTree *kt = KeyTree::create_tree_graph(byte_length, degree, individual_keys, 1);
    const lkh_gc_state gc_state{kt};

    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
    std::vector<lkh_message> join_messages;
    if (use_kor) {
        join_messages = lkh_join_kor_gc(gc_state, join_user, join_ind_key);
    } else {
        join_messages = lkh_join_uor_gc(gc_state, join_user, join_ind_key);
    }
    long join_new_size = 0;
    long join_old_size_sum = 0;
    std::vector<long> join_msgs_per_user(size);
    std::vector<long> join_bytes_per_user(size);
    for (const auto& message : join_messages) {
        if (message.receivers.contains(join_user)) {
            join_new_size = message.data.size();
        } else {
            join_old_size_sum += message.data.size();
            for (auto receiver: message.receivers) {
                ++join_msgs_per_user[receiver-1];
                join_bytes_per_user[receiver-1] += message.data.size();
            }
        }
    }
    /*
    auto [mean, stddev] = calculate_mean_stddev(join_msgs_per_user.data(), join_msgs_per_user.size());
    auto [mean2, stddev2] = calculate_mean_stddev(join_bytes_per_user.data(), join_bytes_per_user.size());
     */
    std::cout << "%" << "LKH (" << rekeying_string << ") Join New Message Size: " << join_new_size << std::endl;
    std::cout << "%" << "LKH (" << rekeying_string << ") Join Old Message Size Sum: " << join_old_size_sum << std::endl;
    /*
    std::cout << "%" << "LKH (" << rekeying_string << ") Join Old Message Nums Avg: " << mean << " " << stddev << std::endl;
    std::cout << "%" << "LKH (" << rekeying_string << ") Join Old Message Sizes Avg: " << mean2 << " " << stddev2 << std::endl;
     */
    if (use_kor) {
        lkh_leave_kor_gc(gc_state, join_user);
    } else {
        lkh_leave_uor_gc(gc_state, join_user);
    }

    std::vector<lkh_message> leave_messages;
    if (use_kor) {
        leave_messages = lkh_leave_kor_gc(gc_state, leave_user);
    } else {
        leave_messages = lkh_leave_uor_gc(gc_state, leave_user);
    }
    long leave_size_sum = 0;
    std::vector<long> leave_msgs_per_user(size-1);
    std::vector<long> leave_bytes_per_user(size-1);
    for (const auto& message : leave_messages) {
        leave_size_sum += message.data.size();
        for (auto receiver: message.receivers) {
            ++leave_msgs_per_user[receiver-1];
            leave_bytes_per_user[receiver-1] += message.data.size();
        }
    }
    /*
    auto [mean3, stddev3] = calculate_mean_stddev(leave_msgs_per_user.data(), leave_msgs_per_user.size());
    auto [mean4, stddev4] = calculate_mean_stddev(leave_bytes_per_user.data(), leave_bytes_per_user.size());
     */
    std::cout << "%" << "LKH (" << rekeying_string << ") Leave Message Size Sum: " << leave_size_sum << std::endl;
    /*
    std::cout << "%" << "LKH (" << rekeying_string << ") Leave Message Nums Avg: " << mean3 << " " << stddev3 << std::endl;
    std::cout << "%" << "LKH (" << rekeying_string << ") Leave Message Sizes Avg: " << mean4 << " " << stddev4 << std::endl;
     */
}
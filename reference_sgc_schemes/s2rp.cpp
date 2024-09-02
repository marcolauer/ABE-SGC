#include "s2rp.h"

#include <chrono>
#include <map>
#include <cstring>
#include <iostream>
#include <iomanip>
#include "../config.h"
#include "../HashChain.h"
#include "../KeyTree.h"
#include "../random.h"
#include "../crypto_functions/sha256.h"
#include "../crypto_functions/aes.h"
#include "../serialize.h"

#if MASTER_DEVICE == MASTER_PC
#include <random>
#elif MASTER_DEVICE == MASTER_ESP32
#include "esp_random.h"
#endif

// Dini and Savino - S2RP: A secure and Scalable Rekeying Protocol for Wireless Sensor Networks - 2006

using ID_TYPE = uint16_t;

// Important: byte length <= 32 (Because of Sha-256)
constexpr int byte_length = 16;

enum s2rp_msg_type {
    KeyMessage, KeyReconfigureMessage, CommandMessage, CommandReconfigureMessage, CommandReconfigureInitMessage, JoinKeyMessage, DeleteMessage
};

struct s2rp_gc_state {
    std::vector<unsigned char> join_key{};
    HashChain *command_chain{};
    std::vector<unsigned char> communication_key{};
    KeyTree *key_tree{};
};

struct s2rp_gm_state {
    std::vector<unsigned char> individual_key{};
    std::vector<unsigned char> join_key{};
    std::vector<unsigned char> command_key{};
    std::vector<unsigned char> communication_key{};
    ID_TYPE group_size{};
    // Subgroups are indexed with their size => unique for a single user
    std::map<ID_TYPE, std::vector<unsigned char>> group_keys;
};

struct s2rp_message {
    std::set<ID_TYPE> receivers;
    std::vector<unsigned char> data{};
};

std::vector<unsigned char> s2rp_encrypt_with_hash(const std::vector<unsigned char>& key, const std::vector<unsigned char>& message) {
    std::vector<unsigned char> hash = sha256(message);
    hash.resize(byte_length);
    std::vector result(message);
    result.insert(result.end(), hash.begin(), hash.end());
    return aes_encrypt(key, result);
}

std::vector<unsigned char> s2rp_decrypt_and_verify_hash(const std::vector<unsigned char>& key, const std::vector<unsigned char>& message) {
    std::vector<unsigned char> plaintext = aes_decrypt(key, message);
    std::vector<unsigned char> hash = sha256(std::vector(plaintext.begin(), plaintext.begin() + byte_length));
    hash.resize(byte_length);
    if (memcmp(hash.data(), plaintext.data() + byte_length, byte_length) != 0) {
        std::cerr << "Decrypted data and hash do not match" << std::endl;
        exit(-1);
    }
    plaintext.resize(byte_length);
    return plaintext;
}

// Only used with join_op = false (True would be needed for Cluster Keys)
std::vector<unsigned char> s2rp_choose_key(const s2rp_gm_state& gm_state, const ID_TYPE key_num, const bool join_op) {
    std::vector<unsigned char> key;
    if (key_num == 1) {
        key = gm_state.individual_key;
    } else {
        key = gm_state.group_keys.at(key_num);
        if (join_op) {
            key = bytes_xor(key, gm_state.join_key, byte_length);
        }
    }
    return key;
}

std::vector<s2rp_message> s2rp_initialize_gc(s2rp_gc_state& gc_state) {
    KeyTree *kt = gc_state.key_tree;
    // Update communication key
    gc_state.communication_key = bytes_xor(kt->get_group_key(), gc_state.join_key, byte_length);
    // Messages
    std::vector<s2rp_message> messages;
    for (const auto i : kt->get_all_positions()) {
        std::set<int> subgroup_members = kt->get_members(i);
        const int subgroup_size = subgroup_members.size();
        if (subgroup_size > 1) {
            for (const auto j : subgroup_members) {
                std::vector<unsigned char> message{KeyReconfigureMessage, 'j'};
                // Indicates with which key the message is encrypted (subgroup size)
                serialize_int<ID_TYPE>(message, subgroup_size);
                std::vector<unsigned char> ciphertext = s2rp_encrypt_with_hash(kt->get_key(kt->get_member_position(j)), kt->get_key(i));
                message.insert(message.end(), ciphertext.begin(), ciphertext.end());
                messages.push_back({std::set{static_cast<ID_TYPE>(j)}, message});
            }
        }
    }
    const std::vector<unsigned char> command = gc_state.command_chain->get_current();
    for (const auto i : kt->get_group_members()) {
        const std::vector<unsigned char> key = kt->get_key(kt->get_member_position(i));

        std::vector<unsigned char> command_reconfigure_message{CommandReconfigureInitMessage};
        // Indicates with which key the message is encrypted (subgroup size)
        std::vector<unsigned char> ciphertext = s2rp_encrypt_with_hash(key, command);
        command_reconfigure_message.insert(command_reconfigure_message.end(), ciphertext.begin(), ciphertext.end());
        messages.push_back({std::set{static_cast<ID_TYPE>(i)}, command_reconfigure_message});

        std::vector<unsigned char> join_key_message{JoinKeyMessage};
        // Indicates with which key the message is encrypted (subgroup size)
        std::vector<unsigned char> ciphertext2 = s2rp_encrypt_with_hash(key, gc_state.join_key);
        join_key_message.insert(join_key_message.end(), ciphertext2.begin(), ciphertext2.end());
        messages.push_back({std::set{static_cast<ID_TYPE>(i)}, join_key_message});
    }
    return messages;
}

std::vector<s2rp_message> s2rp_join_gc(s2rp_gc_state& gc_state, const int member_id, const std::vector<unsigned char>& individual_key) {
    std::vector<unsigned char>& join_key = gc_state.join_key;
    HashChain *command_chain = gc_state.command_chain;
    std::vector<unsigned char>& communication_key = gc_state.communication_key;
    KeyTree *kt = gc_state.key_tree;
    keytree_update_data update_data = kt->insert_member(member_id, individual_key, false);
    const std::vector<std::pair<int, std::vector<unsigned char>>>& data_vec = update_data.data_vec;
    std::vector<std::set<int>>& member_vec = update_data.member_vec;
    const int vec_size = member_vec.size();
    // Update join key, command key, and communication key
    const bool command_reconfigure = command_chain->next();
    join_key = sha256(join_key);
    join_key.resize(byte_length);
    communication_key = bytes_xor(kt->get_group_key(), join_key, byte_length);
    // Messages
    std::vector<s2rp_message> messages;
    const std::vector<unsigned char>& command = command_chain->get_current();
    for (int i = vec_size - 1; i >= 0; --i) {
        const int subgroup_size = member_vec.at(i).size();
        if (i > 0) {
            for (const auto x : member_vec.at(i-1)) {
                member_vec.at(i).erase(x);
            }
        }
        if (command_reconfigure) {
            for (const auto j : member_vec.at(i)) {
                std::vector<unsigned char> command_reconfigure_message{CommandReconfigureMessage};
                // Indicates with which key the message is encrypted (subgroup size)
                serialize_int<ID_TYPE>(command_reconfigure_message, subgroup_size);
                std::vector<unsigned char> ciphertext = s2rp_encrypt_with_hash(kt->get_key(kt->get_member_position(j)), command);
                command_reconfigure_message.insert(command_reconfigure_message.end(), ciphertext.begin(), ciphertext.end());
                messages.push_back({std::set{static_cast<ID_TYPE>(j)}, command_reconfigure_message});
            }
        } else {
            std::vector<unsigned char> command_message{CommandMessage};
            serialize_int<ID_TYPE>(command_message, subgroup_size);
            command_message.insert(command_message.end(), command.begin(), command.end());
            messages.push_back({std::set<ID_TYPE>{member_vec.at(i).begin(), member_vec.at(i).end()}, command_message});
        }
    }
    std::vector<unsigned char> command_reconfigure_message{CommandReconfigureInitMessage};
    // Indicates with which key the message is encrypted (subgroup size)
    std::vector<unsigned char> ciphertext = s2rp_encrypt_with_hash(individual_key, command);
    command_reconfigure_message.insert(command_reconfigure_message.end(), ciphertext.begin(), ciphertext.end());
    messages.push_back({std::set{static_cast<ID_TYPE>(member_id)}, command_reconfigure_message});

    std::vector<unsigned char> join_key_message{JoinKeyMessage};
    // Indicates with which key the message is encrypted (subgroup size)
    std::vector<unsigned char> ciphertext2 = s2rp_encrypt_with_hash(individual_key, join_key);
    join_key_message.insert(join_key_message.end(), ciphertext2.begin(), ciphertext2.end());
    messages.push_back({std::set{static_cast<ID_TYPE>(member_id)}, join_key_message});

    // Ordering is important for the user not to override its own values
    for (int i = vec_size - 1; i >= 0; --i) {
        std::vector<unsigned char> message{KeyReconfigureMessage, 'j'};
        // Indicates with which key the message is encrypted (subgroup size)
        serialize_int<ID_TYPE>(message, data_vec.at(i).first);
        std::vector<unsigned char> ciphertext3 = s2rp_encrypt_with_hash(individual_key, data_vec.at(i).second);
        message.insert(message.end(), ciphertext3.begin(), ciphertext3.end());
        messages.push_back({std::set{static_cast<ID_TYPE>(member_id)}, message});
    }
    // When a new subgroup has been added, the subgroup key must be sent to the sibling of the added member
    if (member_vec.at(0).size() == 1) {
        const int sibling = *member_vec.at(0).cbegin();
        std::vector<unsigned char> message{KeyReconfigureMessage, 'j'};
        // Indicates with which key the message is encrypted (subgroup size)
        serialize_int<ID_TYPE>(message, data_vec.at(0).first);
        std::vector<unsigned char> ciphertext4 = s2rp_encrypt_with_hash(kt->get_key(kt->get_member_position(sibling)), data_vec.at(0).second);
        message.insert(message.end(), ciphertext4.begin(), ciphertext4.end());
        messages.push_back({std::set{static_cast<ID_TYPE>(sibling)}, message});
    }
    return messages;
}

std::vector<s2rp_message> s2rp_leave_gc(s2rp_gc_state& gc_state, const int member_id) {
    const std::vector<unsigned char>& join_key = gc_state.join_key;
    std::vector<unsigned char>& communication_key = gc_state.communication_key;
    KeyTree *kt = gc_state.key_tree;
    keytree_update_data update_data = kt->remove_member(member_id);
    const std::vector<std::vector<unsigned char>>& key_vec = update_data.key_vec;
    const std::vector<std::pair<int, std::vector<unsigned char>>>& data_vec = update_data.data_vec;
    const std::vector<std::set<int>>& member_vec = update_data.member_vec;
    std::vector<bool>& reconfigure_vec = update_data.reconfigure_vec;
    const std::vector<int>& children_vec = update_data.children_vec;
    const bool gk_delete = update_data.gk_delete;
    // Update communication key
    communication_key = bytes_xor(kt->get_group_key(), join_key, byte_length);
    // Messages
    const int sib_size = children_vec.size();
    if (sib_size == 0) {
        const std::set<int> members = kt->get_group_members();
        return std::vector<s2rp_message>{
            {std::set<ID_TYPE>{members.begin(), members.end()}, std::vector<unsigned char>{DeleteMessage}}
        };
    }
    std::vector<s2rp_message> messages;
    int k = 0;
    // Ordering is important for the user not to override its own values
    for (int i = 0; i < sib_size; ++i) {
        for (int j = 0; j < children_vec.at(i); ++j) {
            const unsigned char action = gk_delete && i == 0 && j == 0 ? 'L': 'l';
            if (reconfigure_vec.at(i)) {
                for (const auto l : member_vec.at(k)) {
                    std::vector message{KeyReconfigureMessage, action};
                    // Indicates with which key the message is encrypted (subgroup size)
                    serialize_int<ID_TYPE>(message, data_vec.at(i).first);
                    std::vector<unsigned char> ciphertext = s2rp_encrypt_with_hash(kt->get_key(kt->get_member_position(l)), data_vec.at(i).second);
                    message.insert(message.end(), ciphertext.begin(), ciphertext.end());
                    messages.push_back({std::set{static_cast<ID_TYPE>(l)}, message});
                }
            } else {
                std::vector message{KeyMessage, action};
                // Indicates with which key the message is encrypted (subgroup size)
                serialize_int<ID_TYPE>(message, member_vec.at(k).size());
                serialize_int<ID_TYPE>(message, data_vec.at(i).first);
                std::vector<unsigned char> ciphertext = aes_encrypt(key_vec.at(k), data_vec.at(i).second);
                message.insert(message.end(), ciphertext.begin(), ciphertext.end());
                messages.push_back({std::set<ID_TYPE>{member_vec.at(k).begin(), member_vec.at(k).end()}, message});
            }
            ++k;
        }
    }
    return messages;
}

void s2rp_key_message_gm(s2rp_gm_state& gm_state, const std::vector<unsigned char>& message) {
    int offset = 0;
    const bool gk_delete = message.at(offset++) == 'L';
    const auto decryption_key_num = deserialize_int<ID_TYPE>(message, &offset);
    const auto key_num = deserialize_int<ID_TYPE>(message, &offset);
    const std::vector<unsigned char> decryption_key = s2rp_choose_key(gm_state, decryption_key_num, false);
    const std::vector<unsigned char> plaintext = aes_decrypt(decryption_key, std::vector(message.begin() + offset, message.end()));
    if (gk_delete) {
        const auto it = --gm_state.group_keys.find(key_num + 1);
        gm_state.group_keys.erase(it);
    }
    // Delete the old version of the (sub-)group key (works because top down)
    gm_state.group_keys.erase(key_num + 1);
    // Set the new (sub-)group key
    gm_state.group_keys[key_num] = plaintext;
    if (key_num == gm_state.group_size - 1) {
        --gm_state.group_size;
        gm_state.communication_key = bytes_xor(plaintext, gm_state.join_key, byte_length);
    }
}

void s2rp_key_reconfigure_message_gm(s2rp_gm_state& gm_state, const std::vector<unsigned char>& message) {
    int offset = 0;
    const bool join_op = message.at(offset) == 'j';
    const bool gk_delete = message.at(offset++) == 'L';
    const auto key_num = deserialize_int<ID_TYPE>(message, &offset);
    const std::vector<unsigned char> plaintext = s2rp_decrypt_and_verify_hash(gm_state.individual_key, std::vector(message.begin() + offset, message.end()));
    if (gk_delete) {
        const auto it = --gm_state.group_keys.find(key_num + 1);
        gm_state.group_keys.erase(it);
    }

    // Set the new (sub-)group key
    gm_state.group_keys[key_num] = plaintext;
    // Manage Group Size
    // Only happens for Initialization
    if (join_op) {
        if (key_num > gm_state.group_size) {
            gm_state.group_size = key_num;
            if (gm_state.join_key.size() != 0) {
                gm_state.communication_key = bytes_xor(plaintext, gm_state.join_key, byte_length);
            }
        }
    } else {
        // In join_op this message is only used to update the key, not to change the key_nums
        // Delete the old version of the (sub-)group key (works because top down)
        gm_state.group_keys.erase(key_num + 1);

        if (key_num == gm_state.group_size - 1) {
            --gm_state.group_size;
            gm_state.communication_key = bytes_xor(plaintext, gm_state.join_key, byte_length);
        }
    }
}

void s2rp_command_message_gm(s2rp_gm_state& gm_state, const std::vector<unsigned char>& message) {
    int offset = 0;
    const auto key_num = deserialize_int<ID_TYPE>(message, &offset);
    const auto command_key = std::vector(message.begin() + offset, message.begin() + offset + byte_length);
    std::vector<unsigned char> hash = sha256(command_key);
    hash.resize(byte_length);
    if (memcmp(hash.data(), gm_state.command_key.data(), byte_length) != 0) {
        std::cerr << "H(command) != old_command" << std::endl;
        exit(-1);
    }

    std::vector<ID_TYPE> keys;
    std::map<ID_TYPE, std::vector<unsigned char>>::iterator it;
    if (key_num == 1) {
        it = gm_state.group_keys.begin();
    } else {
        it = gm_state.group_keys.find(key_num);
    }
    for (; it != gm_state.group_keys.cend(); ++it) {
        keys.push_back(it->first);
    }
    for (auto it2 = keys.rbegin(); it2 != keys.rend(); ++it2) {
        const std::vector<unsigned char> move_key = gm_state.group_keys.at(*it2);
        gm_state.group_keys.erase(*it2);
        gm_state.group_keys[*it2 + 1] = move_key;
    }
    ++gm_state.group_size;

    gm_state.command_key = command_key;
    gm_state.join_key = sha256(gm_state.join_key);
    gm_state.join_key.resize(byte_length);
    gm_state.communication_key = bytes_xor(gm_state.group_keys.at(gm_state.group_size), gm_state.join_key, byte_length);
}

void s2rp_command_reconfigure_message_gm(s2rp_gm_state& gm_state, const std::vector<unsigned char>& message) {
    int offset = 0;
    const auto key_num = deserialize_int<ID_TYPE>(message, &offset);
    gm_state.command_key = s2rp_decrypt_and_verify_hash(gm_state.individual_key, std::vector(message.begin() + offset, message.end()));
    std::vector<ID_TYPE> keys;
    std::map<ID_TYPE, std::vector<unsigned char>>::iterator it;
    if (key_num == 1) {
        it = gm_state.group_keys.begin();
    } else {
        it = gm_state.group_keys.find(key_num);
    }
    for (; it != gm_state.group_keys.cend(); ++it) {
        keys.push_back(it->first);
    }
    for (auto it2 = keys.rbegin(); it2 != keys.rend(); ++it2) {
        const std::vector<unsigned char> move_key = gm_state.group_keys.at(*it2);
        gm_state.group_keys.erase(*it2);
        gm_state.group_keys[*it2 + 1] = move_key;
    }
    ++gm_state.group_size;
    gm_state.join_key = sha256(gm_state.join_key);
    gm_state.join_key.resize(byte_length);
    gm_state.communication_key = bytes_xor(gm_state.group_keys.at(gm_state.group_size), gm_state.join_key, byte_length);
}

void s2rp_command_reconfigure_message_init_gm(s2rp_gm_state& gm_state, const std::vector<unsigned char>& message) {
    gm_state.command_key = s2rp_decrypt_and_verify_hash(gm_state.individual_key, std::vector(message.begin(), message.end()));
}

void s2rp_join_key_message_gm(s2rp_gm_state& gm_state, const std::vector<unsigned char>& message) {
    const std::vector<unsigned char> plaintext = s2rp_decrypt_and_verify_hash(gm_state.individual_key, std::vector(message.begin(), message.end()));
    gm_state.join_key = plaintext;
    if (gm_state.group_size > 1) {
        gm_state.communication_key = bytes_xor(gm_state.group_keys.at(gm_state.group_size), plaintext, byte_length);
    }
}

void s2rp_update_gm(s2rp_gm_state& gm_state, const std::vector<unsigned char>& message) {
    const auto message_type = static_cast<s2rp_msg_type>(message.at(0));
    const auto rest = std::vector(message.begin() + 1, message.end());
    if (message_type == KeyMessage) {
        s2rp_key_message_gm(gm_state, rest);
    } else if (message_type == KeyReconfigureMessage) {
        s2rp_key_reconfigure_message_gm(gm_state, rest);
    } else if (message_type == CommandMessage) {
        s2rp_command_message_gm(gm_state, rest);
    } else if (message_type == CommandReconfigureMessage) {
        s2rp_command_reconfigure_message_gm(gm_state, rest);
    } else if (message_type == CommandReconfigureInitMessage) {
        s2rp_command_reconfigure_message_init_gm(gm_state, rest);
    } else if (message_type == JoinKeyMessage) {
        s2rp_join_key_message_gm(gm_state, rest);
    } else if (message_type == DeleteMessage) {
        gm_state.group_keys.clear();
        gm_state.communication_key.clear();
        gm_state.group_size = 1;
    } else {
        std::cerr << "Unknown message type" << std::endl;
        exit(-1);
    }
}

// Mention: No periodic rekeying implemented
// Possible: When server memory is limited, use the Coppersmith und Jakobsson method to store hashchains
void s2rp_test(const int size, const int degree, const bool print_tree) {
    constexpr int chain_length = 3;
    const int join_user = size + 1;
    constexpr int leave_user = 1;
    std::vector<unsigned char> join_key = byte_vector_random(byte_length);
    std::vector<std::pair<int, std::vector<unsigned char>>> individual_keys(size);
    for (int i = 0; i < size; ++i) {
        individual_keys[i] = {i+1, byte_vector_random(byte_length)};
    }
    KeyTree *kt = KeyTree::create_tree_graph(byte_length, degree, individual_keys, chain_length);
    s2rp_gc_state gc_state{
        join_key, HashChain::create_chain(byte_length, chain_length),
        std::vector<unsigned char>(), kt
    };
    std::map<int, s2rp_gm_state> gm_states;
    for (const auto& [user, individual_key] : individual_keys) {
        gm_states[user] = s2rp_gm_state{
            individual_key, std::vector<unsigned char>(), std::vector<unsigned char>(),
            std::vector<unsigned char>(), 1,
            std::map<ID_TYPE, std::vector<unsigned char>>()
        };
    }
    // Initialization
    std::vector<s2rp_message> init_messages = s2rp_initialize_gc(gc_state);
    if (print_tree) {
        kt->print();
    }
    for (const auto& [receivers, message] : init_messages) {
        for (const auto receiver : receivers) {
            s2rp_update_gm(gm_states.at(receiver), message);
        }
    }

    // Join Values Initialization
    std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
    gm_states[join_user] = s2rp_gm_state{join_ind_key};

    // Join
    std::vector<s2rp_message> join_messages = s2rp_join_gc(gc_state, join_user, join_ind_key);
    if (print_tree) {
        kt->print();
    }
    for (const auto& [receivers, message] : join_messages) {
        for (const auto receiver : receivers) {
            s2rp_update_gm(gm_states.at(receiver), message);
        }
    }

    // Leave
    std::vector<s2rp_message> leave_messages = s2rp_leave_gc(gc_state, leave_user);
    if (print_tree) {
        kt->print();
    }
    for (const auto& [receivers, message] : leave_messages) {
        for (const auto receiver : receivers) {
            s2rp_update_gm(gm_states.at(receiver), message);
        }
    }

    const std::set<int> group_members = kt->get_group_members();
    for (const auto& [user, state] : gm_states) {
        if (group_members.contains(user)) {
            if (std::memcmp(gc_state.communication_key.data(), state.communication_key.data(), byte_length) != 0) {
                std::cerr << "S2RP: The communication key of user " << user << " does not match the server communication key";
                exit(-1);
            }
        }
    }
    std::cout << "S2RP: The server communication key matches all user communication keys" << std::endl;

    // Cleanup
    delete gc_state.command_chain;
    delete gc_state.key_tree;
}

void s2rp_run_gc(const int size, const int degree, const int chain_length, const int precision, const int repetitions) {
    std::chrono::steady_clock::time_point begin;
    std::chrono::steady_clock::time_point end;

    std::vector<unsigned char> join_key = byte_vector_random(byte_length);
    std::vector<std::pair<int, std::vector<unsigned char>>> individual_keys(size);
    for (int i = 0; i < size; ++i) {
        individual_keys[i] = {i+1, byte_vector_random(byte_length)};
    }
    KeyTree *kt = KeyTree::create_tree_graph(byte_length, degree, individual_keys, chain_length);
    s2rp_gc_state gc_state{
        join_key, HashChain::create_chain(byte_length, chain_length),
        std::vector<unsigned char>(), kt
    };

    long gc_join_times[repetitions];
    long gc_leave_times[repetitions];

    for (int i = 0; i < repetitions; ++i) {
        // Join
        const int join_user = size + 1;
        const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
        begin = std::chrono::steady_clock::now();
        s2rp_join_gc(gc_state, join_user, join_ind_key);
        end = std::chrono::steady_clock::now();
        gc_join_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        s2rp_leave_gc(gc_state, join_user);
    }
    auto [mean, stddev] = calculate_mean_stddev(gc_join_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "S2RP GC Join Time: Avg: " << mean << " " << stddev << std::endl;

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
        s2rp_leave_gc(gc_state, leave_user);
        end = std::chrono::steady_clock::now();
        gc_leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();

        const std::vector<unsigned char> leave_join_ind_key = byte_vector_random(byte_length);
        s2rp_join_gc(gc_state, leave_user, leave_join_ind_key);
    }
    auto [mean2, stddev2] = calculate_mean_stddev(gc_leave_times, repetitions);
    std::cout << "%" << "S2RP GC Leave Time: " << mean2 << " " << stddev2 << std::endl;

    // Cleanup
    delete gc_state.command_chain;
    delete gc_state.key_tree;
}

void s2rp_generate_messages(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key,
                            const int size, const int degree, const int chain_length, const int repetitions) {
    int message_counter = 0;
    const int user = size + 1;
    std::vector<unsigned char> join_key = byte_vector_random(byte_length);
    std::vector<std::pair<int, std::vector<unsigned char>>> individual_keys(size);
    for (int i = 0; i < size; ++i) {
        individual_keys[i] = {i+1, byte_vector_random(byte_length)};
    }
    KeyTree *kt = KeyTree::create_tree_graph(byte_length, degree, individual_keys, chain_length);
    s2rp_gc_state gc_state{
            join_key, HashChain::create_chain(byte_length, chain_length),
            std::vector<unsigned char>(), kt
    };

    for (int i = 0; i < repetitions; ++i) {
        std::vector<s2rp_message> join_messages = s2rp_join_gc(gc_state, user, join_ind_key);
        for (const auto& [receivers, message] : join_messages) {
            if (receivers.contains(user)) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }
        if (i != repetitions - 1) {
            s2rp_leave_gc(gc_state, user);
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

        std::vector<s2rp_message> join_leave_messages = s2rp_leave_gc(gc_state, replace_user);
        for (const auto& [receivers, message] : join_leave_messages) {
            if (receivers.contains(user)) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }

        const std::vector<unsigned char> replace_ind_key = byte_vector_random(byte_length);
        std::vector<s2rp_message> join_messages = s2rp_join_gc(gc_state, replace_user, replace_ind_key);
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
    std::vector<s2rp_message> join_leave_messages = s2rp_leave_gc(gc_state, replace_user);
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

        std::vector<s2rp_message> leave_messages = s2rp_leave_gc(gc_state, leave_user);
        for (const auto& [receivers, message] : leave_messages) {
            if (receivers.contains(user)) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }

        const std::vector<unsigned char> leave_join_ind_key = byte_vector_random(byte_length);
        std::vector<s2rp_message> leave_join_messages = s2rp_join_gc(gc_state, leave_user, leave_join_ind_key);
        for (const auto& [receivers, message] : leave_join_messages) {
            if (receivers.contains(user)) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }
    }

    // Cleanup
    delete gc_state.key_tree;
}

void s2rp_run_gm(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key, const int precision,
                const int repetitions) {
    std::chrono::steady_clock::time_point begin;
    std::chrono::steady_clock::time_point end;

    int message_counter = 0;

    // Initialization
    s2rp_gm_state gm_state{};
    gm_state.individual_key = join_ind_key;
    gm_state.group_size = 1;

    long gm_join_new_times[repetitions];

    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        begin = std::chrono::steady_clock::now();
        s2rp_update_gm(gm_state, message);
        end = std::chrono::steady_clock::now();
        gm_join_new_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();

        if (i != repetitions - 1) {
            gm_state.group_keys.clear();
            gm_state.group_size = 1;
        }
    }

    auto [mean, stddev] = calculate_mean_stddev(gm_join_new_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "S2RP GM Max. Join New Time: " << mean << " " << stddev << std::endl;

    long gm_join_old_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message1 = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        s2rp_update_gm(gm_state, message1);
        const std::vector<unsigned char> message2 = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        begin = std::chrono::steady_clock::now();
        s2rp_update_gm(gm_state, message2);
        end = std::chrono::steady_clock::now();
        gm_join_old_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }

    auto [mean2, stddev2] = calculate_mean_stddev(gm_join_old_times, repetitions);
    std::cout << "%" << "S2RP GM Max. Join Old Time: " << mean2 << " " << stddev2 << std::endl;


    const std::vector<unsigned char> message = load_bytes_from_file(
            file_prefix + std::to_string(message_counter++));
    s2rp_update_gm(gm_state, message);

    long gm_leave_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message1 = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        begin = std::chrono::steady_clock::now();
        s2rp_update_gm(gm_state, message1);
        end = std::chrono::steady_clock::now();
        gm_leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        const std::vector<unsigned char> message2 = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        s2rp_update_gm(gm_state, message2);
    }
    auto [mean3, stddev3] = calculate_mean_stddev(gm_leave_times, repetitions);
    std::cout << "%" << "S2RP GM Max. Leave Time: " << mean3 << " " << stddev3 << std::endl;
}

void s2rp_measure_byte_lengths(const int size, const int degree, const int chain_length) {
    const int join_user = size + 1;
    const int leave_user = size;
    std::vector<unsigned char> join_key = byte_vector_random(byte_length);
    std::vector<std::pair<int, std::vector<unsigned char>>> individual_keys(size);
    for (int i = 0; i < size; ++i) {
        individual_keys[i] = {i+1, byte_vector_random(byte_length)};
    }
    KeyTree *kt = KeyTree::create_tree_graph(byte_length, degree, individual_keys, chain_length);
    s2rp_gc_state gc_state{
            join_key, HashChain::create_chain(byte_length, chain_length),
            std::vector<unsigned char>(), kt
    };

    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);

    int repetitions = 100;
    std::vector<long> join_new_size_sums(repetitions);
    std::vector<long> join_old_size_sums(repetitions);
    std::vector<long> leave_size_sums(repetitions);

    for (int i = 0; i < repetitions; ++i) {
        std::vector<s2rp_message> join_messages = s2rp_join_gc(gc_state, join_user, join_ind_key);
        for (const auto& message : join_messages) {
            if (message.receivers.contains(join_user)) {
                join_new_size_sums[i] += message.data.size();
            } else {
                join_old_size_sums[i] += message.data.size();
            }
        }
        s2rp_leave_gc(gc_state, join_user);
        std::vector<s2rp_message> leave_messages = s2rp_leave_gc(gc_state, leave_user);
        for (const auto& message : leave_messages) {
            leave_size_sums[i] += message.data.size();
        }
        s2rp_join_gc(gc_state, leave_user, join_ind_key);
    }

    auto [mean, stddev] = calculate_mean_stddev(join_new_size_sums.data(), repetitions);
    auto [mean2, stddev2] = calculate_mean_stddev(join_old_size_sums.data(), repetitions);
    auto [mean3, stddev3] = calculate_mean_stddev(leave_size_sums.data(), repetitions);
    std::cout << "%" << "S2RP Join New Message Size: " << mean << " " << stddev << std::endl;
    std::cout << "%" << "S2RP Join Old Message Size Sum: " << mean2 << " " << stddev2 << std::endl;
    std::cout << "%" << "S2RP Leave Message Size Sum: " << mean3 << " " << stddev3 << std::endl;

}
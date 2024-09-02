#include "KeyTree.h"
#include <iostream>
#include <queue>
#include <climits>
#include <algorithm>

KeyTree *KeyTree::create_star_graph(const int byte_length,
                                    const std::vector<std::pair<int, std::vector<unsigned char>>>& members,
                                    const int chain_length) {
    return create_tree_graph(byte_length,INT_MAX, members, chain_length);
}

KeyTree *KeyTree::create_tree_graph(const int byte_length, const int degree,
                                    const std::vector<std::pair<int, std::vector<unsigned char>>> &members,
                                    const int chain_length) {
    const int num_members = members.size();
    if (num_members < 1) {
        std::cerr << "KeyTree must have at least one member" << std::endl;
        exit(-1);
    }
    // Ceil((num_members - 1)) / (degree - 1))
    const int num_subgroup_keys = (num_members + degree - 3) / (degree - 1);
    const int size = num_members + num_subgroup_keys;
    const auto keyTree = new KeyTree(byte_length, chain_length, degree, size, num_members, std::vector(size, true),
                    std::vector<HashChain *>(size), std::vector<std::set<int>>(size), std::map<int, int>());
    std::vector<HashChain *>& data = keyTree->data;
    data.reserve(size);
    std::vector<std::set<int>>& ids = keyTree->ids;
    std::map<int, int>& id_to_position = keyTree->id_to_position;
    for (int i = 0; i < num_subgroup_keys; ++i) {
        data[i] = HashChain::create_chain(byte_length, chain_length);
    }
    for (int i = 0; i < num_members; ++i) {
        const int dict_position = i + num_subgroup_keys;
        int member_id = members.at(i).first;
        if (member_id < 1) {
            std::cerr << "invalid member_id" << std::endl;
            exit(-1);
        }
        data[dict_position] = HashChain::from_single_key(members.at(i).second, byte_length);
        ids[dict_position].insert(member_id);
        id_to_position[member_id] = dict_position;
    }
    for (int i = num_subgroup_keys - 1; i >= 0; --i) {
        std::set<int>& node_ids = ids[i];
        for (const auto j : keyTree->get_children(i)) {
            std::set<int>& child_ids = ids[j];
            node_ids.insert(child_ids.cbegin(), child_ids.cend());
        }
    }
    return keyTree;
}

KeyTree::~KeyTree() {
    for (const auto i : get_all_positions()) {
        delete data[i];
    }
}

std::set<int> KeyTree::get_all_positions() const {
    std::set<int> positions;
    for (int i = 0; i < size; ++i) {
        if (dict.at(i)) {
            positions.insert(i);
        }
    }
    return positions;
}

std::set<int> KeyTree::get_members(const int i) const {
    return ids.at(i);
}

std::set<int> KeyTree::get_group_members() const {
    return ids.at(0);
}

int KeyTree::get_group_size() const {
    return num_members;
}

std::vector<unsigned char> KeyTree::get_key(const int i) const {
    return data.at(i)->get_current();
}

std::vector<unsigned char> KeyTree::get_group_key() const {
    return get_key(0);
}

int KeyTree::get_member_position(const int member_id) const {
    return id_to_position.at(member_id);
}

int KeyTree::get_parent(const int i) const {
    return (i - 1) / degree;
}

std::vector<int> KeyTree::get_children(int i) const {
    std::vector<int> result;
    result.reserve(degree);
    i = i * degree + 1;
    for (int j = 0; j < degree; ++j) {
        if (i < size && dict[i]) {
            result.push_back(i);
        }
        ++i;
    }
    return result;
}

std::vector<int> KeyTree::get_siblings(const int i) const {
    std::vector<int> result;
    result.reserve(degree-1);
    int pos = get_parent(i) * degree + 1;
    for (int j = 0; j < degree; ++j) {
        if (pos != i && pos < size && dict[pos]) {
            result.push_back(pos);
        }
        ++pos;
    }
    return result;
}

keytree_update_data KeyTree::insert_member(const int member_id, const std::vector<unsigned char>& individual_key, const bool rekey) {
    if (get_group_members().contains(member_id)) {
        std::cerr << "KeyTree already contains a member with the same member_id" << std::endl;
        exit(-1);
    }
    const auto it = find(dict.cbegin(), dict.cend(), false);
    int pos;
    if (it == dict.cend()) {
        pos = size++;
        dict.push_back(true);
        data.push_back(HashChain::from_single_key(individual_key, byte_length));
        ids.push_back(std::set{member_id});
    } else {
        pos = std::distance(dict.cbegin(), it);
        dict[pos] = true;
        data[pos] = HashChain::from_single_key(individual_key, byte_length);
        ids[pos].insert(member_id);
    }
    id_to_position[member_id] = pos;
    const int parent_pos = get_parent(pos);
    const int pospp = pos + 1;
    if (ids[parent_pos].size() == 1) {
        if (pospp == size) {
            ++size;
            dict.push_back(true);
            data.push_back(data[parent_pos]);
            ids.emplace_back();
        } else {
            dict[pospp] = true;
            data[pospp] = data[parent_pos];
        }
        const int parent_id = *ids[parent_pos].cbegin();
        ids[pospp].insert(parent_id);
        id_to_position[parent_id] = pospp;
        data[parent_pos] = HashChain::create_chain(byte_length, chain_length);
    }

    keytree_update_data update_data{};
    std::vector<std::vector<unsigned char>> reconfigure_vec;
    while (pos != 0) {
        pos = get_parent(pos);
        HashChain *keyChain = data[pos];
        const bool new_subgroup = ids[pos].size() == 1;

        if (rekey) {
            std::vector<unsigned char> old_key;
            if (new_subgroup) {
                old_key = data[pospp]->get_current();
                update_data.reconfigure_vec.push_back(true);
            } else {
                old_key = keyChain->get_current();
                const bool reconfigure = keyChain->next();
                update_data.reconfigure_vec.push_back(reconfigure);
            }
            update_data.key_vec.push_back(old_key);
        }

        update_data.member_vec.push_back(ids[pos]);
        update_data.data_vec.emplace_back(ids[pos].size() + 1, keyChain->get_current());
        ids[pos].insert(member_id);
    }
    ++num_members;
    return update_data;
}

keytree_update_data KeyTree::remove_member(const int member_id) {
    if (!get_group_members().contains(member_id)) {
        std::cerr << "KeyTree does not contain a member with member_id" << std::endl;
        exit(-1);
    }
    int pos = id_to_position[member_id];
    dict[pos] = false;
    delete data[pos];
    ids[pos].clear();
    const int parent_pos = get_parent(pos);
    id_to_position.erase(member_id);

    const std::vector<int> siblings = get_siblings(pos);
    const bool gk_delete = siblings.size() == 1;
    if (gk_delete) {
        const int sibling_pos = *siblings.cbegin();
        delete data[parent_pos];
        data[parent_pos] = data[sibling_pos];
        ids[parent_pos] = std::move(ids[sibling_pos]);
        if (ids[parent_pos].size() == 1) {
            dict[sibling_pos] = false;
            id_to_position[*ids[parent_pos].cbegin()] = parent_pos;
        }
        std::queue<int> to_move;
        to_move.push(sibling_pos);
        while (!to_move.empty()) {
            const int move_pos = to_move.front();
            to_move.pop();
            const int first_child = move_pos - (move_pos - 1) % degree;
            auto move_children = get_children(move_pos);
            for (const auto child : move_children) {
                const int offset = (child - 1) % degree;
                const int destination = first_child + offset;
                dict[destination] = true;
                data[destination] = data[child];
                ids[destination] = std::move(ids[child]);
                if (ids[destination].size() == 1) {
                    dict[child] = false;
                    id_to_position[*ids[destination].cbegin()] = destination;
                } else {
                    to_move.push(child);
                }
            }
        }
        pos = parent_pos;
    }

    cleanup();
    keytree_update_data update_data{};
    update_data.gk_delete = gk_delete;
    if (!gk_delete) {
        const int par = get_parent(pos);
        ids[par].erase(member_id);
        HashChain *keyChain = data[par];
        update_data.reconfigure_vec.push_back(keyChain->next());
        update_data.data_vec.emplace_back(ids[par].size(), keyChain->get_current());
        const std::vector<int> sibs = get_siblings(pos);
        update_data.children_vec.push_back(sibs.size());
        for (const auto i : sibs) {
            update_data.key_vec.push_back(data[i]->get_current());
            update_data.member_vec.push_back(ids[i]);
        }
        pos = par;
    }
    while (pos != 0) {
        const int par = get_parent(pos);
        ids[par].erase(member_id);
        HashChain *keyChain = data[par];
        update_data.reconfigure_vec.push_back(keyChain->next());
        update_data.data_vec.emplace_back(ids[par].size(), keyChain->get_current());
        std::vector<int> sibs = get_siblings(pos);
        update_data.children_vec.push_back(sibs.size() + 1);
        update_data.key_vec.push_back(data[pos]->get_current());
        update_data.member_vec.push_back(ids[pos]);
        for (const auto i : sibs) {
            update_data.key_vec.push_back(data[i]->get_current());
            update_data.member_vec.push_back(ids[i]);
        }
        pos = par;
    }
    --num_members;
    return update_data;
}

void KeyTree::print() {
    int level_count = 0;
    int level_size = 1;
    for (int i = 0; i < size; ++i) {
        if (level_count == level_size) {
            level_count = 0;
            level_size *= degree;
            std::cout << std::endl;
        }
        std::set<int>& subgroup_members = ids[i];
        std::cout << "{";
        if (!subgroup_members.empty()) {
            for (auto it = subgroup_members.cbegin(); it != --subgroup_members.cend(); ++it) {
                std::cout << *it << ",";
            }
            std::cout << *--subgroup_members.cend();
        }
        std::cout << "}\t";
        ++level_count;
    }
    std::cout << std::endl;
}

// Private Functions

KeyTree::KeyTree(const int byte_length, const int chain_length, const int degree, const int size, const int num_members, std::vector<bool> dict,
                 std::vector<HashChain *> data, std::vector<std::set<int>> ids, std::map<int, int> id_to_position) {
    this->byte_length = byte_length;
    this->chain_length = chain_length;
    this->degree = degree;
    this->size = size;
    this->num_members = num_members;
    this->dict = std::move(dict);
    this->data = std::move(data);
    this->ids = std::move(ids);
    this->id_to_position = std::move(id_to_position);
}

void KeyTree::cleanup() {
    int i = size - 1;
    while (!dict[i--]) {
        dict.pop_back();
        data.pop_back();
        ids.pop_back();
        --size;
    }
}





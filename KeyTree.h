#ifndef MASTER_KEYTREE_H
#define MASTER_KEYTREE_H

#include <vector>
#include <set>
#include <map>
#include "HashChain.h"

/**
 * The data needed to send update messages to the members of a KeyTree after a member has joined or left.
 */
struct keytree_update_data {
    /**
     * Keys to encrypt the update messages with, sorted from leaf to root.
     * Empty for rekey=false in insert_member.
     */
    std::vector<std::vector<unsigned char>> key_vec;
    /**
     * Pairs of subgroup sizes and updated keys for updating the member keys, sorted from leaf to root.
     */
    std::vector<std::pair<int, std::vector<unsigned char>>> data_vec;
    /**
     * Receiving members for each message, sorted from leaf to root.
     */
    std::vector<std::set<int>> member_vec;
    /**
     * Booleans indicating whether HashChains of the updated nodes needed to be reconfigured or not, sorted from leaf
     * to root.
     */
    std::vector<bool> reconfigure_vec;
    /**
     * Number of children of an updated node, sorted from leaf to root; only used in remove_member.
     */
    std::vector<int> children_vec;
    /**
     * Indicates if the parent node of the removed leaf node in remove_member was also removed, as it only had one
     * child left.
     */
    bool gk_delete;
};

/**
 * Tree data structure containing keys for Logical Key Hierarchy (LKH) Secure Group Communication (SGC) schemes.
 * Each node contains a HashChain with multiple keys in it. Uses an array implementation of the tree.
 */
class KeyTree {
public:
    /**
     * Creates a KeyTree in with the highest possible degree (i.e. only the root and leaves exist).
     * @param[in] byte_length the length of the contained keys in bytes.
     * @param[in] members a vector containing the user ids and their individual keys.
     * @param[in] chain_length the length of the used HashChains.
     * @returns a pointer to the KeyTree.
     */
    [[nodiscard]] static KeyTree *create_star_graph(int byte_length, const std::vector<std::pair<int, std::vector<unsigned char>>>& members, int chain_length);

    /**
     * Creates a KeyTree in with a specifiable degree.
     * @param[in] byte_length the length of the contained keys in bytes.
     * @param[in] degree the degree of the tree nodes.
     * @param[in] members a vector containing the user ids and their individual keys.
     * @param[in] chain_length the length of the used HashChains.
     * @returns a pointer to the KeyTree.
     */
    [[nodiscard]] static KeyTree *create_tree_graph(int byte_length, int degree, const std::vector<std::pair<int, std::vector<unsigned char>>>& members, int chain_length);

    ~KeyTree();

    /**
     * Gets all indices containing nodes of the tree.
     * @returns a set containing the indices.
     */
    [[nodiscard]] std::set<int> get_all_positions() const;

    /**
     * Gets the member ids of the node at index i.
     * @param[in] i the index of the node.
     * @returns a set containing the ids.
     */
    [[nodiscard]] std::set<int> get_members(int i) const;

    /**
     * Gets all member ids contained in the KeyTree.
     * @returns a set containing the ids.
     */
    [[nodiscard]] std::set<int> get_group_members() const;

    /**
     * Gets the number of all members contained in the KeyTree.
     * @returns the number of members.
     */
    [[nodiscard]] int get_group_size() const;

    /**
     * Gets the current key of the node at index i.
     * @param[in] i the index of the node.
     * @returns a byte vector containing the key.
     */
    [[nodiscard]] std::vector<unsigned char> get_key(int i) const;

    /**
     * Gets the current group key (the key at the root).
     * @returns a byte vector containing the key.
     */
    [[nodiscard]] std::vector<unsigned char> get_group_key() const;

    /**
     * Gets the index of the leaf node of the member with the id member_id.
     * @param[in] member_id the id of the member.
     * @returns the index.
     */
    [[nodiscard]] int get_member_position(int member_id) const;

    /**
     * Gets the index of the parent node of the node at index i.
     * @param[in] i the index of the node.
     * @returns the index of the parent node.
     */
    [[nodiscard]] int get_parent(int i) const;

    /**
     * Gets the indices of all child nodes of the node at index i.
     * @param[in] i the index of the node.
     * @returns a vector containing the indices of the child nodes.
     */
    [[nodiscard]] std::vector<int> get_children(int i) const;

    /**
     * Gets the indices of all sibling nodes of the node at index i.
     * @param[in] i the index of the node.
     * @returns a vector containing the indices of the sibling nodes.
     */
    [[nodiscard]] std::vector<int> get_siblings(int i) const;

    /**
     * Inserts a new member into the KeyTree.
     * @param[in] member_id the id of the new member.
     * @param[in] individual_key the individual key of the new member.
     * @param[in] rekey whether the key of the ancestor nodes of the new node should be updated or not.
     * @returns the data needed to send update messages to the group members.
     */
    [[nodiscard]] keytree_update_data insert_member(int member_id, const std::vector<unsigned char>& individual_key, bool rekey = true);

    /**
     * Deletes a member from the KeyTree.
     * @param[in] member_id the id of the member to delete.
     * @returns the data needed to send update messages to the group members.
     */
    [[nodiscard]] keytree_update_data remove_member(int member_id);

    /**
     * Prints the members of all nodes of the tree.
     */
    void print();
private:
    KeyTree(int byte_length, int chain_length, int degree, int size, int num_members, std::vector<bool> dict,
            std::vector<HashChain *> data, std::vector<std::set<int>> ids, std::map<int, int> id_to_position);
    /**
     * The length of the contained keys in bytes.
     */
    int byte_length;
    /**
     * The length of the used HashChains.
     */
    int chain_length;
    /**
     * The degree of the tree nodes.
     */
    int degree;
    /**
     * The number of nodes use in the tree.
     */
    int size;
    /**
     * The number of all members contained in the tree.
     */
    int num_members;
    /**
     * Helper data structure showing which node slots of the array implementation are populated (in "data" and "ids").
     */
    std::vector<bool> dict;
    /**
     * Contains the HashChains stored in the nodes of the tree. If dict[i] == true, data[i] contains a valid HashChain.
     */
    std::vector<HashChain *> data;
    /**
     * Contains the member ids associated with the tree nodes (the leave node ids of the subtrees of the nodes).
     */
    std::vector<std::set<int>> ids;
    /**
     * Associates member ids with the positions of the leaf nodes of the members.
     */
    std::map<int, int> id_to_position;
    /**
     * Reduces the size of the implementation arrays (dict, data, ids) by removing unused node slots in the end
     * (where dict[i]=false).
     */
    void cleanup();
};

#endif //MASTER_KEYTREE_H

#ifndef MASTER_HASHCHAIN_H
#define MASTER_HASHCHAIN_H

#include <vector>

/**
 * Hash Chain, as introduced by Lamport (<a href="https://doi.org/10.1145/358790.358797">Link</a>).
 * It points to a "current" element, which is the currently used key in the chain.
 */
class HashChain {
public:
    /**
     * Creates a hash chain of length one.
     * @param[in] byte_length the length of the contained key in bytes.
     * @returns the created hash chain.
     */
    [[nodiscard]] static HashChain *create_single(int byte_length);
    /**
     * Creates a hash chain of variable length.
     * @param[in] byte_length the length of the contained keys in bytes.
     * @param[in] length the length of the hash chain.
     * @returns the created hash chain.
     */
    [[nodiscard]] static HashChain *create_chain(int byte_length, int length);
    /**
     * Creates a hash chain of length one containing a specific key.
     * @param[in] byte_length the length of the contained key in bytes.
     * @returns the created hash chain.
     */
    [[nodiscard]] static HashChain *from_single_key(const std::vector<unsigned char>& key, int byte_length);
    /**
     * Creates a hash chain.
     * @param chain a vector of keys to be contained in the hash chain.
     * @param length the length of the hash chain.
     * @param current an integer saying which key is currently pointed at.
     * @param byte_length the length of the contained keys in bytes.
     */
    HashChain(std::vector<std::vector<unsigned char>> chain, int length, int current,  int byte_length);
    /**
     * @returns the currently used key of the hash chain.
     */
    [[nodiscard]] std::vector<unsigned char> get_current() const;
    /**
     * Moves the "current" pointer to the next node in the chain. If the "current" pointer is already at the end of the
     * chain, the hash chain is reconfigured (filled with new random keys) and the pointer is set to the beginning.
     * @returns true if the hash chain has been reconfigured; false otherwise.
     */
    bool next();
private:
    /**
     * The hash chain (a vector of keys).
     */
    std::vector<std::vector<unsigned char>> chain;
    /**
     * The length of the hash chain.
     */
    int length;
    /**
     * An integer saying which key is currently pointed at.
     */
    int current;
    /**
     * The length of the contained keys in bytes.
     */
    int byte_length;
    /**
     * Fills the hash chain with new random keys.
     */
    void reconfigure();
};


#endif //MASTER_HASHCHAIN_H

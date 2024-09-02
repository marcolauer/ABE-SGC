#ifndef MASTER_TTREE_H
#define MASTER_TTREE_H

#include <vector>

/**
 * Threshold-Gate Access Tree:
 * Can either be a Threshold Node or an Attribute Node.
 * @see TThreshold
 * @see TAttribute
 */
class TTree {
public:
    virtual ~TTree() = default;
    [[nodiscard]] virtual TTree *clone() const = 0;
    /**
     * @returns the maximal occurrence count in the tree.
     */
    [[nodiscard]] virtual int get_max_occurrence() const = 0;
};

/**
 * Threshold Node:
 * A threshold node is fulfilled if at least t of the n child nodes are fulfilled.
 * Equivalent AOTree nodes:
 * AND node: t=n=2;
 * OR node: t=1, n=2.
 * @see AOTree
 * @see AOAnd
 * @see AOOr
 */
class TThreshold final : public TTree {
public:
    TThreshold(int t, int n, std::vector<TTree *> children);
    TThreshold(const TThreshold& node);
    ~TThreshold() override;
    [[nodiscard]] TTree *clone() const override;
    /**
     * @returns the number of child nodes that need to be fulfilled for the threshold node to be fulfilled.
     */
    [[nodiscard]] int get_t() const;
    /**
     * @returns the number of child nodes of the threshold node.
     */
    [[nodiscard]] int get_n() const;
    /**
     * The i-th child node of the Tree.
     * @param[in] i the index of the child node.
     * @returns the chosen child node.
     */
    [[nodiscard]] TTree* get_child(int i) const;
    /**
     * @returns the child nodes of the Tree.
     */
    [[nodiscard]] std::vector<TTree *> get_children();
    /**
     * @returns the maximal occurrence count in the tree.
     */
    [[nodiscard]] int get_max_occurrence() const override;
private:
    /**
     * The number of child nodes that need to be fulfilled for the threshold node to be fulfilled.
     */
    int t;
    /**
     * The number of child nodes of the threshold node.
     */
    int n;
    /**
     * The child nodes of the Tree.
     */
    std::vector<TTree *> children;
};

/**
 * Attribute Node:
 * An attribute node is fulfilled if the user possesses the contained attribute.
 */
class TAttribute final : public TTree {
public:
    explicit TAttribute(int attribute);
    TAttribute(int attribute, int occurrence);
    TAttribute(const TAttribute& node);
    ~TAttribute() override;
    bool operator <(const TAttribute& other) const;
    [[nodiscard]] TTree *clone() const override;
    /**
     * @returns the identifier of the attribute.
     */
    [[nodiscard]] int get_attribute() const;
    /**
     * @returns how often the same attribute has already occurred in the tree.
     */
    [[nodiscard]] int get_occurrence() const;
    /**
     * @returns the maximal occurrence count in the tree.
     */
    [[nodiscard]] int get_max_occurrence() const override;
private:
    /**
     * The identifier of the attribute.
     */
    int attribute;
    /**
     * How often the same attribute has already occurred in the tree.
     */
    int occurrence;
};

#endif //MASTER_TTREE_H
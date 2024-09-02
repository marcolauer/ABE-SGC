#ifndef MASTER_AOTREE_H
#define MASTER_AOTREE_H

#include "TTree.h"

/**
 *  AND-OR-Gate Access Tree:
 *  A binary tree representing boolean formulas.
 *  Can be an AND Node, an OR Node, or an Attribute Node.
 *  @see AOAnd
 *  @see AOOr
 *  @see AOAttribute
 */
class AOTree {
public:
    virtual ~AOTree() = default;
    [[nodiscard]] virtual AOTree *clone() const = 0;
    /**
     * Converts this AND-OR-Gate Access Tree into the corresponding Threshold-Gate Access Tree.
     * @returns the Threshold-Gate Access Tree.
     **/
    [[nodiscard]] virtual TTree *to_TTree() const = 0;
};

/**
 *  AND Node:
 *  An AND node is fulfilled if both child nodes are fulfilled.
 */
class AOAnd final: public AOTree {
public:
    AOAnd(AOTree *node1, AOTree *node2);
    AOAnd(const AOAnd& node);
    ~AOAnd() override;
    [[nodiscard]] AOTree *clone() const override;
    /**
     * @returns the first child node.
     */
    [[nodiscard]] AOTree *get_child1() const;
    /**
     * @returns the second child node.
     */
    [[nodiscard]] AOTree *get_child2() const;
    /**
     * Converts this AND node into the corresponding Threshold-Gate Access Tree.
     * @returns the Threshold-Gate Access Tree.
     **/
    [[nodiscard]] TTree *to_TTree() const override;
private:
    /**
     * The first child node.
     */
    AOTree *child1;
    /**
     * The second child node.
     */
    AOTree *child2;
};

/**
 *  OR Node:
 *  An OR node is fulfilled if at least one child node is fulfilled.
 */
class AOOr final: public AOTree {
public:
    AOOr(AOTree *node1, AOTree *node2);
    AOOr(const AOOr& node);
    ~AOOr() override;
    [[nodiscard]] AOTree *clone() const override;
    /**
     * @returns the first child node.
     */
    [[nodiscard]] AOTree *get_child1() const;
    /**
     * @returns the second child node.
     */
    [[nodiscard]] AOTree *get_child2() const;
    /**
     * Converts this OR node into the corresponding Threshold-Gate Access Tree.
     * @returns the Threshold-Gate Access Tree.
     **/
    [[nodiscard]] TTree *to_TTree() const override;
private:
    /**
     * The first child node.
     */
    AOTree *child1;
    /**
     * The second child node.
     */
    AOTree *child2;
};

/**
 *  Attribute Node:
 *  An attribute node is fulfilled if the user possesses the contained attribute.
 */
class AOAttribute final: public AOTree {
public:
    explicit AOAttribute(int attribute);
    AOAttribute(int attribute, int occurrence);
    AOAttribute(const AOAttribute& node);
    ~AOAttribute() override;
    bool operator <(const AOAttribute& other) const;
    [[nodiscard]] AOTree *clone() const override;
    /**
     * @returns the identifier of the attribute.
     */
    [[nodiscard]] int get_attribute() const;
    /**
     * @returns how often the same attribute has already occurred in the tree.
     */
    [[nodiscard]] int get_occurrence() const;
    /**
     * Converts this attribute node into the corresponding Threshold-Gate Access Tree.
     * @returns the Threshold-Gate Access Tree.
     **/
    [[nodiscard]] TTree *to_TTree() const override;
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

#endif //MASTER_AOTREE_H
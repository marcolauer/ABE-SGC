#ifndef MASTER_MSPMATRIX_H
#define MASTER_MSPMATRIX_H

#include <vector>
#include <optional>
#include "AOTree.h"
#include "TTree.h"

extern "C" {
#include <relic.h>
}

/**
 *  MSP (Monotone Span Program) Attribute:
 *  An attribute used in a MSP matrix.
 *  @see MSPMatrix
 */
class MSPAttribute final {
public:
    explicit MSPAttribute(int attribute);
    MSPAttribute(int attribute, int occurrence);
    MSPAttribute(const MSPAttribute& node);
    bool operator <(const MSPAttribute& other) const;
    /**
     * @returns the identifier of the attribute.
     */
    [[nodiscard]] int get_attribute() const;
    /**
     * @returns how often the same attribute has already occurred in the matrix.
     */
    [[nodiscard]] int get_occurrence() const;
private:
    /**
     * The identifier of the attribute.
     */
    int attribute;
    /**
     * How often the same attribute has already occurred in the matrix.
     */
    int occurrence;
};

/**
 *  Share-generating matrix of an MSP (Monotone Span Program), as used in Linear Secret Sharing Schemes (LSSS).
 */
class MSPMatrix {
public:
    /**
     * Transforms an AND-OR-Gate Access Tree into a MSP matrix using the
     * <a href="https://eprint.iacr.org/2010/351.pdf">Lewko-Waters Algorithm</a> (Appendix G).
     * @param[in] node the AND-OR-Gate Access Tree.
     * @param[in] order the order of the finite field.
     * @returns a pointer to the MSP matrix.
     */
    [[nodiscard]] static MSPMatrix *from_AOTree(AOTree *node, bn_t order);

    /**
     * Transforms an AND-OR-Gate Access Tree into a MSP matrix using the
     * <a href="https://eprint.iacr.org/2010/351.pdf">Lewko-Waters Algorithm</a> (Appendix G).
     * This algorithm variant only keeps the rows associated with attributes that the user possesses.
     * @param[in] node the AND-OR-Gate Access Tree.
     * @param[in] attributes the attributes of the decrypting user.
     * @param[in] order the order of the finite field.
     * @returns a pointer to the MSP matrix.
     */
    [[nodiscard]] static std::optional<MSPMatrix *> from_AOTree_decrypt(AOTree *node, const std::vector<int>& attributes, bn_t order);

    /**
     * Transforms a Threshold-Gate Access Tree into a MSP matrix using the
     * <a href="https://eprint.iacr.org/2010/374.pdf">Algorithm by Liu et al.</a>.
     * @param[in] node the Threshold-Gate Access Tree.
     * @param[in] order the order of the finite field.
     * @returns a pointer to the MSP matrix.
     */
    [[nodiscard]] static MSPMatrix *from_TTree(TTree *node, bn_t order);

    /**
     * Transforms a Threshold-Gate Access Tree into a MSP matrix using the
     * <a href="https://eprint.iacr.org/2010/374.pdf">Algorithm by Liu et al.</a>.
     * This algorithm variant only keeps the rows associated with attributes that the user possesses.
     * @param[in] node the Threshold-Gate Access Tree.
     * @param[in] attributes the attributes of the decrypting user.
     * @param[in] order the order of the finite field.
     * @returns a pointer to the MSP matrix (if it is possible to construct one).
     */
    [[nodiscard]] static std::optional<MSPMatrix *> from_TTree_decrypt(TTree *node, const std::vector<int>& attributes, bn_t order);

    /**
     * Creates a MSP matrix.
     * @param[in] rows the number of rows of the matrix.
     * @param[in] cols the number of columns of the matrix.
     * @param[in] matrix the matrix in form of two nested vectors.
     * @param[in] row_to_attr the attributes associated to each row of the matrix.
     * @returns the MSP matrix.
     */
    MSPMatrix(int rows, int cols, std::vector<std::vector<bn_t *>> matrix, std::vector<MSPAttribute> row_to_attr);

    /**
     * Destructor frees the multiple precision integer values in the MSP matrix.
     */
    ~MSPMatrix();

    /**
     * Gets the number of rows of the MSP matrix.
     * @returns the number of rows.
     */
    [[nodiscard]] int get_rows() const;

    /**
     * Gets the number of columns of the MSP matrix.
     * @returns the number of columns.
     */
    [[nodiscard]] int get_cols() const;

    /**
     * Gets the i-th row of the MSP matrix.
     * @param[in] i the row of the MSP matrix.
     * @returns a vector containing the row.
     */
    [[nodiscard]] std::vector<bn_t *> get_row(int i);

    /**
     * Gets the attribute associated with the i-th row of the MSP matrix.
     * @param[in] i the row of the MSP matrix.
     * @returns the attribute.
     */
    [[nodiscard]] MSPAttribute get_attr_from_row(int i) const;

    /**
     * Prints the content of the MSP matrix.
     */
    void print() const;
private:
    /**
     * Implements the functionality for the public methods from_TTree and from_TTree_decrypt.
     * @param node the Threshold-Gate Access Tree.
     * @param for_decrypt whether to use the optimized algorithm for decryption only or not.
     * @param attributes the attributes of the decrypting user (required for the algorithm optimized for decryption).
     * @param order the order of the finite field.
     * @returns a pointer to the MSP matrix (if it is possible to construct one).
     */
    static std::optional<MSPMatrix *> from_TTree(TTree *node, bool for_decrypt, const std::vector<int>& attributes, bn_t order);
    /**
     * The number of rows of the MSP matrix.
     */
    int rows;
    /**
     * The number of columns of the MSP matrix.
     */
    int cols;
    /**
     * The MSP matrix containing the multiple precision integers.
     */
    std::vector<std::vector<bn_t *>> matrix;
    /**
     * Associates the rows of the MSP matrix with their attributes.
     * @see MSPAttribute
     */
    std::vector<MSPAttribute> row_to_attr;
};

#endif //MASTER_MSPMATRIX_H

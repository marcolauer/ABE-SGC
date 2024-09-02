#ifndef MASTER_SKDC_H
#define MASTER_SKDC_H

#include <vector>
#include <string>

/**
 * Tests the functionality of the SKDC SGC scheme and prints the result.
 * @param[in] size the group size.
 */
void skdc_test(int size);

/**
 * Measures and prints the average runtimes and standard deviation for the join and leave operations on the group
 * controller.
 * @param[in] size the group size.
 * @param[in] precision how many digits to print after the decimal point of the runtimes.
 * @param[in] repetitions how many repetitions to perform for each measurement.
 */
void skdc_run_gc(int size, int precision, int repetitions);

/**
 * Generates and saves update the key update messages for the group members for the measurements on the group members.
 * @param[in] file_prefix file prefix for saving the files to the filesystem. The full file names are
 *      <file_prefix><counter>.bin
 * @param[in] join_ind_key the individual key that only the joining user and the group controller share.
 * @param[in] size the group size.
 * @param[in] repetitions how many repetitions to perform for each measurement.
 */
void skdc_generate_messages(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key,
                                 int size, int repetitions);

/**
 * Measures and prints the average runtimes and standard deviation for the join and leave operations on a group member.
 * It loads the update messages from the filesystem.
 * @param[in] file_prefix file prefix for loading the files from the disk. The full file names are
 *      <file_prefix><counter>.bin
 * @param[in] join_ind_key the individual key that only the joining user and the group controller share.
 * @param[in] precision how many digits to print after the decimal point of the runtimes.
 * @param[in] repetitions how many repetitions to perform for each measurement.
 */
void skdc_run_gm(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key,
                      int precision, int repetitions);

/**
 * Measures and prints the sizes of the key update messages generated by the group controller for joining and leaving
 * the group.
 * @param[in] size the group size.
 */
void skdc_measure_byte_lengths(int size);

#endif //MASTER_SKDC_H

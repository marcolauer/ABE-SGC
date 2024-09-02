#ifndef MASTER_CONFIG_H
#define MASTER_CONFIG_H

// The configuration contained in this header file can be changed to select the device on which the code is executed.

/** A PC (with Linux / WSL2) */
#define MASTER_PC 0
/** An ESP32 */
#define MASTER_ESP32 1
/**
 * On which device the code should be run. Options: MASTER_PC, MASTER_ESP32.
 */
#define MASTER_DEVICE MASTER_PC

/**
 * The universe size of the small-universe ABE schemes.
 */
#define MASTER_UNIVERSE_SIZE 200

/**
 * The id length for the Flat Table ABE SGC variant.
 * Recommended value: ceil(log2(MASTER_UNIVERSE_SIZE)).
 */
#define MASTER_FT_ID_LENGTH 8

#endif //MASTER_CONFIG_H

# General Information

This project can be configured to run on a PC (with Linux / via WSL2) or on an ESP32.
This can be done in `config.h` by setting `MASTER_DEVICE` to either `MASTER_PC` or `MASTER_ESP32`.
`config.h` also includes some options for configuring the universe size of small universe ABE schemes 
`MASTER_UNIVERSE_SIZE` and the size of the user ids in the Flat Table Variant of ABE SGC `MASTER_FT_ID_LENGTH`.
Other parameters can be set in `main.cpp`.

# Dependencies
## On the PC and ESP32
- [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) (Already comes with ESP-IDF)
- [RELIC toolkit](https://github.com/relic-toolkit/relic) (See below how to compile)
## On the PC only
- [Espresso logic minimizer](https://github.com/classabbyamp/espresso-logic)
- [Minbool](https://github.com/madmann91/minbool)

# Compiling RELIC
## On the PC
Execute `scripts/install_relic_pc.sh`.
## On the ESP32

The RELIC toolkit needs to be slightly modified to be able to access the RNG of the ESP32.

Create the file `src/rand/relic_rand_esp32.c` with the following content:
```
#include "relic_conf.h"
#include "relic_core.h"
#include "relic_rand.h"
#include "esp_random.h"

#if RAND == ESP32

void rand_bytes(uint8_t *buf, size_t size) {
    esp_fill_random(buf, size);
}

void rand_seed(uint8_t *buf, size_t size) {
    /* Do nothing, mark as seeded. */
    core_get()->seeded = 1;
}

#endif
```

In `include/relic_conf.h.in`, add the following to the definitions of the random generator and random generator seeder:
```
/** ESP32. */
#define ESP32    5
```
In `include/relic_rand.h`, add the following at the definition of the size of the PRNG internal state:
```
#elif RAND == ESP32
#define RLC_RAND_SIZE      0
#endif
```


Next, RELIC needs to be compiled as a component in ESP-IDF.
Use the following configuration in the corresponding `CMakeLists.txt`:
```
set(WSIZE 32)       # Build RELIC as a 32- bit library
set(OPSYS DUINO)    # Enable printing to the serial output of the ESP32
set(RAND ESP32)     # Use the ESP32 RNG
set(SEED ESP32)     # Use the ESP32 RNG
set(SHLIB OFF)      # Do not build a shared library
set(BENCH 0)        # No Benchmarks
set(TESTS 0)        # No Tests
set(WITH DV BN FP EP EC CP MD FPX EPX PP PC) # Required library parts
set(FP_PRIME 381)   # Use the BLS12 -381 Elliptic Curve
set(CHECK OFF)      # Otherwise memory access errors will occur
```
Further,
- Require the component `esp_hw_support` in the corresponding `idf_component_register` function call
- Compile with `-Wno-error=stringop-overflow -Wnoerror=array-parameter` and `-mlongcalls`

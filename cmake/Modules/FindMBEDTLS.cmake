find_path(MBEDTLS_INCLUDE_DIR mbedtls_config.h PATHS "/usr/local/include/mbedtls")
find_library(MBEDTLS_LIBRARY NAMES mbedcrypto PATHS "/usr/local/lib")

include (FindPackageHandleStandardArgs)
find_package_handle_standard_args(MBEDTLS DEFAULT_MSG MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY)

if(MBEDTLS_FOUND)
    set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY})
    set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
endif()
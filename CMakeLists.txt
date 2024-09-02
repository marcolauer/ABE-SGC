#CMakeLists.txt for running the project on a normal PC
cmake_minimum_required(VERSION 3.5)
project(Master)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_FLAGS "-std=c99")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(MBEDTLS REQUIRED)
find_package(RELIC REQUIRED)
find_package(MINBOOL REQUIRED)

include_directories(${MBEDTLS_INCLUDE_DIRS})
include_directories(${RELIC_INCLUDE_DIRS})
include_directories(${MINBOOL_INCLUDE_DIRS})

add_executable(${PROJECT_NAME}
        main.cpp
        util.cpp
        util.h
        MSPMatrix.cpp
        MSPMatrix.h
        AOTree.cpp
        AOTree.h
        TTree.cpp
        TTree.h
        secret_sharing.cpp
        secret_sharing.h
        crypto_functions/aes.cpp
        crypto_functions/aes.h
        crypto_functions/sha256.cpp
        crypto_functions/sha256.h
        random.cpp
        random.h
        HashChain.cpp
        HashChain.h
        KeyTree.cpp
        KeyTree.h
        relic_util.cpp
        relic_util.h
        abe_schemes/fibe.cpp
        abe_schemes/fibe.h
        abe_schemes/fibe_large.cpp
        abe_schemes/fibe_large.h
        abe_schemes/kpabe.cpp
        abe_schemes/kpabe.h
        abe_schemes/kpabe_large.cpp
        abe_schemes/kpabe_large.h
        abe_schemes/cpabe.cpp
        abe_schemes/cpabe.h
        abe_schemes/fame_kpabe.cpp
        abe_schemes/fame_kpabe.h
        abe_schemes/fame_cpabe.cpp
        abe_schemes/fame_cpabe.h
        abe_schemes/fabeo_kpabe.cpp
        abe_schemes/fabeo_kpabe.h
        abe_schemes/fabeo_cpabe.cpp
        abe_schemes/fabeo_cpabe.h
        serialize.cpp
        serialize.h
        reference_sgc_schemes/lkh.cpp
        reference_sgc_schemes/lkh.h
        reference_sgc_schemes/s2rp.cpp
        reference_sgc_schemes/s2rp.h
        reference_sgc_schemes/skdc.cpp
        reference_sgc_schemes/skdc.h
        abe_schemes/kpabe_switcher.cpp
        abe_schemes/kpabe_switcher.h
        abe_schemes/cpabe_switcher.cpp
        abe_schemes/cpabe_switcher.h
        abe_sgc_schemes/naive_cpabe.cpp
        abe_sgc_schemes/naive_cpabe.h
        abe_sgc_schemes/flat_table.cpp
        abe_sgc_schemes/flat_table.h
        config.h
        abe_sgc_schemes/naive_kpabe.cpp
        abe_sgc_schemes/naive_kpabe.h
        abe_schemes/kpabbe.cpp
        abe_schemes/kpabbe.h
        abe_schemes/fibe_s.cpp
        abe_schemes/fibe_s.h
        abe_schemes/fibe_large_s.cpp
        abe_schemes/fibe_large_s.h
        abe_schemes/kpabe_s.cpp
        abe_schemes/kpabe_s.h
        abe_schemes/kpabe_large_s.cpp
        abe_schemes/kpabe_large_s.h
        abe_schemes/cpabe_s.cpp
        abe_schemes/cpabe_s.h
        abe_schemes/cpabbe.cpp
        abe_schemes/cpabbe.h
        bfm/espresso.h
        abe_sgc_schemes/kpabbe_sgc.cpp
        abe_sgc_schemes/kpabbe_sgc.h
        abe_sgc_schemes/cpabbe_sgc.cpp
        abe_sgc_schemes/cpabbe_sgc.h
        abe_schemes/kpabbe_s.cpp
        abe_schemes/kpabbe_s.h
        abe_schemes/cpabbe_s.cpp
        abe_schemes/cpabbe_s.h
        abe_schemes/cpabbe_switcher.cpp
        abe_schemes/cpabbe_switcher.h
        abe_schemes/kpabbe_switcher.cpp
        abe_schemes/kpabbe_switcher.h
)

target_link_libraries(${PROJECT_NAME} ${MBEDTLS_LIBRARIES} ${RELIC_LIBRARIES})
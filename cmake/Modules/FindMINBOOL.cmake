find_path(MINBOOL_INCLUDE_DIR minbool.h PATHS "/usr/local/include/minbool")

include (FindPackageHandleStandardArgs)
find_package_handle_standard_args(MINBOOL DEFAULT_MSG MINBOOL_INCLUDE_DIR)

if(MINBOOL_FOUND)
    set(MINBOOL_INCLUDE_DIRS ${MINBOOL_INCLUDE_DIR})
endif()
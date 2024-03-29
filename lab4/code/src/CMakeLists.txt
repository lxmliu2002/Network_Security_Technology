aux_source_directory (. SRC_LIST)

set(CMAKE_CXX_COMPILER g++)

include_directories (../include)

add_executable (MD5 ${SRC_LIST})

set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

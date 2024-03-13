aux_source_directory (. SRC_LIST)

include_directories (../include)

add_executable (chat ${SRC_LIST})

set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

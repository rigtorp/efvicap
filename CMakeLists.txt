cmake_minimum_required(VERSION 3.6)

set(CMAKE_EXPORT_COMPILE_COMMANDS "true")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(efvicap VERSION "1.1.0" LANGUAGES CXX)

include(FindPackageHandleStandardArgs)

find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
find_package_handle_standard_args(PCAP DEFAULT_MSG
        PCAP_LIBRARY
        PCAP_INCLUDE_DIR)

find_path(EFVI_INCLUDE_DIR NAMES etherfabric/ef_vi.h)
find_library(EFVI_LIBRARY NAMES ciul1)
find_package_handle_standard_args(EFVI DEFAULT_MSG
        EFVI_LIBRARY
        EFVI_INCLUDE_DIR)

add_executable(efvicap efvicap.cpp)
target_include_directories(efvicap
        PRIVATE
        ${PCAP_INCLUDE_DIR}
        ${EFVI_INCLUDE_DIR})
target_link_libraries(efvicap
        ${PCAP_LIBRARY}
        ${EFVI_LIBRARY})

install(TARGETS efvicap RUNTIME DESTINATION bin)

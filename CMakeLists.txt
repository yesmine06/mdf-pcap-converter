cmake_minimum_required(VERSION 3.15)
project(mdf2ascii VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

# mdflib (deps/mdflib, zlib + expat via vcpkg)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(MDF_BUILD_TOOL OFF CACHE BOOL "" FORCE)
set(MDF_BUILD_TEST OFF CACHE BOOL "" FORCE)
add_subdirectory(deps/mdflib mdflib-build EXCLUDE_FROM_ALL)

add_executable(mdf2ascii
    main.cpp
    ConversionManager.cpp
    mdf/MdfReader.cpp
    mdf/MdfFrameWriter.cpp
    ascii/AsciiReader.cpp
    bus/BusDetector.cpp
    pcap/PcapWriter.cpp
    pcap/PcapNgWriter.cpp
    pcap/PcapReader.cpp
    pcap/PcapNgReader.cpp
)

target_include_directories(mdf2ascii PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/mdflib/include
)

target_link_libraries(mdf2ascii PRIVATE mdf)

# Tests de non-regression
add_executable(run_tests
    tests/run_tests.cpp
    ConversionManager.cpp
    mdf/MdfReader.cpp
    mdf/MdfFrameWriter.cpp
    ascii/AsciiReader.cpp
    bus/BusDetector.cpp
    pcap/PcapWriter.cpp
    pcap/PcapNgWriter.cpp
    pcap/PcapReader.cpp
    pcap/PcapNgReader.cpp
)
target_include_directories(run_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/mdflib/include
)
target_link_libraries(run_tests PRIVATE mdf)

enable_testing()
add_test(NAME conversion_regression
    COMMAND run_tests ${CMAKE_SOURCE_DIR}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

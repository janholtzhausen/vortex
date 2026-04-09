cmake_minimum_required(VERSION 3.20)

# Fuzzer targets require clang + libFuzzer
set(FUZZ_FLAGS "-fsanitize=fuzzer,address,undefined")

# HTTP parser fuzzer — pulls in just the file that contains parse_http_request_line
add_executable(fuzz_http_parser
    fuzz_http_parser.c
    ${CMAKE_SOURCE_DIR}/src/worker_proxy.c
)

target_include_directories(fuzz_http_parser PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/generated
)

# worker_proxy.c has conditional includes; provide stubs via defines so it
# compiles as a standalone unit without pulling in the full worker runtime.
target_compile_definitions(fuzz_http_parser PRIVATE
    VORTEX_FUZZ_STANDALONE=1
)

target_compile_options(fuzz_http_parser PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_http_parser PRIVATE ${FUZZ_FLAGS})

# Seed corpus directory — checked in alongside the fuzzer
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/corpus)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/corpus_seeds.txt
    ${CMAKE_CURRENT_BINARY_DIR}/corpus/seed0
    COPYONLY
)

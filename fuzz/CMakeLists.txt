cmake_minimum_required(VERSION 3.20)

set(FUZZ_FLAGS "-fsanitize=fuzzer,address,undefined")

set(FUZZ_INCDIRS
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/generated
)
set(FUZZ_DEFS VORTEX_FUZZ_STANDALONE=1)

# Seed corpus: copy all files from fuzz/corpus/ into build corpus dir
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/corpus)
file(GLOB CORPUS_SEEDS "${CMAKE_CURRENT_SOURCE_DIR}/corpus/*.txt"
                        "${CMAKE_CURRENT_SOURCE_DIR}/corpus/seed_*")
foreach(seed ${CORPUS_SEEDS})
    get_filename_component(seed_name "${seed}" NAME)
    configure_file("${seed}" "${CMAKE_CURRENT_BINARY_DIR}/corpus/${seed_name}" COPYONLY)
endforeach()
# Legacy single-file seed
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/corpus_seeds.txt
    ${CMAKE_CURRENT_BINARY_DIR}/corpus/seed_legacy
    COPYONLY
)

# ── fuzz_http_parser: parse_http_request_line ──────────────────────────────
add_executable(fuzz_http_parser
    fuzz_http_parser.c
    ${CMAKE_SOURCE_DIR}/src/worker_proxy.c
    ${CMAKE_SOURCE_DIR}/src/tsc_cal.c
)
target_include_directories(fuzz_http_parser PRIVATE ${FUZZ_INCDIRS})
target_compile_definitions(fuzz_http_parser PRIVATE ${FUZZ_DEFS})
target_compile_options(fuzz_http_parser PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_http_parser PRIVATE ${FUZZ_FLAGS})

# ── fuzz_smuggling: request framing ambiguity / count_header ───────────────
add_executable(fuzz_smuggling
    fuzz_smuggling.c
    ${CMAKE_SOURCE_DIR}/src/worker_proxy.c
    ${CMAKE_SOURCE_DIR}/src/tsc_cal.c
)
target_include_directories(fuzz_smuggling PRIVATE ${FUZZ_INCDIRS})
target_compile_definitions(fuzz_smuggling PRIVATE ${FUZZ_DEFS})
target_compile_options(fuzz_smuggling PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_smuggling PRIVATE ${FUZZ_FLAGS})

# ── fuzz_chunked: chunked_decode_append ────────────────────────────────────
add_executable(fuzz_chunked
    fuzz_chunked.c
    ${CMAKE_SOURCE_DIR}/src/chunked.c
    ${CMAKE_SOURCE_DIR}/src/simd.c
)
target_include_directories(fuzz_chunked PRIVATE ${FUZZ_INCDIRS})
target_compile_definitions(fuzz_chunked PRIVATE ${FUZZ_DEFS})
target_compile_options(fuzz_chunked PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_chunked PRIVATE ${FUZZ_FLAGS})

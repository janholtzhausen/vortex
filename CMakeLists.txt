cmake_minimum_required(VERSION 3.20)
project(vortex C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()

set(VORTEX_VERSION_OVERRIDE "" CACHE STRING "Override the Vortex version string for package builds")
if(VORTEX_VERSION_OVERRIDE)
    set(VORTEX_VERSION "${VORTEX_VERSION_OVERRIDE}")
else()
    file(READ "${CMAKE_SOURCE_DIR}/VERSION" VORTEX_VERSION_RAW)
    string(STRIP "${VORTEX_VERSION_RAW}" VORTEX_VERSION)
endif()
configure_file(
    "${CMAKE_SOURCE_DIR}/include/version.h.in"
    "${CMAKE_BINARY_DIR}/generated/version.h"
    @ONLY
)

# ---- Build type flags ----
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(VORTEX_MARCH "native" CACHE STRING "GCC/Clang -march value (native, x86-64-v3, znver3, etc.)")
set(CMAKE_C_FLAGS_RELEASE        "-O3 -march=${VORTEX_MARCH} -mtune=${VORTEX_MARCH} -DNDEBUG -flto -D_FORTIFY_SOURCE=2 -fstack-protector-strong")
set(CMAKE_C_FLAGS_DEBUG          "-O0 -g3 -fsanitize=address,undefined -DVORTEX_DEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG -D_FORTIFY_SOURCE=2 -fstack-protector-strong")

# Common warnings.
# -Werror=format-security: format-string vulnerabilities are always hard errors.
add_compile_options(
    -Wall -Wextra -Wno-unused-parameter -Wno-stringop-truncation
    -Wformat -Wformat-security -Werror=format-security
)

option(VORTEX_FUZZ "Build libFuzzer targets" OFF)

# ---- Dependencies ----
find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBBPF REQUIRED libbpf)
if(NOT LIBBPF_FOUND)
    message(FATAL_ERROR "libbpf not found. Install: apt-get install libbpf-dev")
endif()

pkg_check_modules(LIBURING REQUIRED liburing)
if(NOT LIBURING_FOUND)
    message(FATAL_ERROR "liburing not found. Install: apt-get install liburing-dev")
endif()

pkg_check_modules(YAML REQUIRED yaml-0.1)
if(NOT YAML_FOUND)
    message(FATAL_ERROR "libyaml not found. Install: apt-get install libyaml-dev")
endif()

pkg_check_modules(NGHTTP2 libnghttp2)
if(NGHTTP2_FOUND)
    message(STATUS "nghttp2: ${NGHTTP2_VERSION} — HTTP/2 frontend enabled")
else()
    message(STATUS "nghttp2: not found — HTTP/2 disabled (apt-get install libnghttp2-dev)")
endif()

# ---- picotls (required for TLS phase) ----
set(PICOTLS_SRC_DIR "/tmp/picotls" CACHE PATH "picotls source dir")
set(PICOTLS_BUILD_DIR "/tmp/picotls/build" CACHE PATH "picotls build dir")
if(EXISTS "${PICOTLS_SRC_DIR}/include/picotls.h" AND
   EXISTS "${PICOTLS_BUILD_DIR}/libpicotls-core.a" AND
   EXISTS "${PICOTLS_BUILD_DIR}/libpicotls-minicrypto.a")
    set(PICOTLS_AVAILABLE TRUE)
    message(STATUS "picotls found at ${PICOTLS_SRC_DIR}")
else()
    set(PICOTLS_AVAILABLE FALSE)
    message(WARNING "picotls not found at ${PICOTLS_SRC_DIR} — TLS phase will not compile")
endif()

# ---- BPF compilation ----
find_program(CLANG_BPF clang REQUIRED)

# Generate vmlinux.h from running kernel if not present
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/bpf/vmlinux.h")
    message(STATUS "Generating bpf/vmlinux.h from running kernel...")
    execute_process(
        COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c
        OUTPUT_FILE "${CMAKE_SOURCE_DIR}/bpf/vmlinux.h"
        RESULT_VARIABLE VMLINUX_RESULT
        ERROR_VARIABLE  VMLINUX_ERROR
    )
    if(NOT VMLINUX_RESULT EQUAL 0)
        message(WARNING "bpftool vmlinux.h generation failed: ${VMLINUX_ERROR}")
        message(WARNING "BPF compilation may fail without vmlinux.h")
    else()
        message(STATUS "Generated bpf/vmlinux.h")
    endif()
endif()

# Detect BPF include path
execute_process(
    COMMAND ${CLANG_BPF} -print-file-name=include
    OUTPUT_VARIABLE CLANG_INCLUDE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_custom_command(
    OUTPUT  "${CMAKE_BINARY_DIR}/vortex_xdp.bpf.o"
    COMMAND ${CLANG_BPF}
            -O2 -g
            -target bpf
            -D__BPF__
            -D__TARGET_ARCH_x86
            -I${CMAKE_SOURCE_DIR}/bpf
            -I${LIBBPF_INCLUDE_DIRS}
            -I${CLANG_INCLUDE_DIR}
            -c ${CMAKE_SOURCE_DIR}/bpf/vortex_xdp.bpf.c
            -o "${CMAKE_BINARY_DIR}/vortex_xdp.bpf.o"
    DEPENDS
            bpf/vortex_xdp.bpf.c
            bpf/maps.h
            bpf/vortex_xdp.h
            bpf/vmlinux.h
    COMMENT "Compiling XDP BPF program"
    VERBATIM
)
add_custom_target(bpf_prog ALL DEPENDS "${CMAKE_BINARY_DIR}/vortex_xdp.bpf.o")

# ---- Sources ----
set(VORTEX_SRCS
    src/main.c
    src/log.c
    src/config.c
    src/auth.c
    src/bpf_loader.c
    src/uring.c
    src/conn.c
    src/router.c
    src/worker.c
    src/worker_accept.c
    src/worker_backend.c
    src/worker_cache.c
    src/worker_compress.c
    src/compress_pool.c
    src/worker_proxy.c
    src/pool.c
    src/cache.c
    src/metrics.c
    src/dashboard.c
    src/simd.c
)

if(PICOTLS_AVAILABLE)
    list(APPEND VORTEX_SRCS src/tls.c)
    list(APPEND VORTEX_SRCS src/tls_pool.c)
    if(NGHTTP2_FOUND)
        list(APPEND VORTEX_SRCS src/worker_h2.c)
    endif()
    list(APPEND VORTEX_SRCS cert/static_file.c)
    list(APPEND VORTEX_SRCS cert/acme_client.c cert/acme_http01.c cert/acme_dns01.c cert/dns_cloudflare.c)
endif()

# ---- HTTP/3 via ngtcp2 + nghttp3 (static, linked against OpenSSL 4.0) ----
set(NGTCP2_BUILD_DIR  "/tmp/ngtcp2-1.16-build" CACHE PATH "ngtcp2 build dir")
set(NGHTTP3_BUILD_DIR "/tmp/nghttp3-build"      CACHE PATH "nghttp3 build dir")
set(NGTCP2_SRC_DIR    "/tmp/ngtcp2-1.16.0"      CACHE PATH "ngtcp2 source dir")
set(NGHTTP3_SRC_DIR   "/tmp/nghttp3-1.8.0"      CACHE PATH "nghttp3 source dir")

set(QUIC_AVAILABLE FALSE)
message(STATUS "HTTP/3: disabled (ngtcp2 requires OpenSSL; migrated to picotls)")

add_executable(vortex ${VORTEX_SRCS})
add_dependencies(vortex bpf_prog)

target_include_directories(vortex PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/generated
    ${CMAKE_SOURCE_DIR}/include/cert
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/bpf
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBURING_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
)

if(QUIC_AVAILABLE)
    target_include_directories(vortex PRIVATE
        ${NGTCP2_BUILD_DIR}/lib/includes
        ${NGTCP2_BUILD_DIR}/crypto/includes
        ${NGTCP2_SRC_DIR}/lib/includes
        ${NGTCP2_SRC_DIR}/crypto/includes
        ${NGHTTP3_BUILD_DIR}/lib/includes
        ${NGHTTP3_SRC_DIR}/lib/includes
    )
endif()

target_link_libraries(vortex
    ${LIBBPF_LIBRARIES}
    ${LIBURING_LIBRARIES}
    ${YAML_LIBRARIES}
    pthread
    elf
    z
    brotlienc
)

if(NGHTTP2_FOUND)
    target_compile_definitions(vortex PRIVATE VORTEX_H2=1)
    target_include_directories(vortex PRIVATE ${NGHTTP2_INCLUDE_DIRS})
    target_link_libraries(vortex ${NGHTTP2_LIBRARIES})
    target_link_directories(vortex PRIVATE ${NGHTTP2_LIBRARY_DIRS})
endif()

target_link_directories(vortex PRIVATE
    ${LIBBPF_LIBRARY_DIRS}
    ${YAML_LIBRARY_DIRS}
)

# TLS support via picotls + minicrypto
if(PICOTLS_AVAILABLE)
    target_compile_definitions(vortex PRIVATE VORTEX_PHASE_TLS=1)
    target_include_directories(vortex PRIVATE
        ${PICOTLS_SRC_DIR}/include
        ${PICOTLS_SRC_DIR}/deps/micro-ecc
    )
    target_link_libraries(vortex
        ${PICOTLS_BUILD_DIR}/libpicotls-minicrypto.a
        ${PICOTLS_BUILD_DIR}/libpicotls-core.a
    )
endif()

# HTTP/3 static link — ngtcp2 + nghttp3 + ngtcp2_crypto_ossl (all vs OpenSSL 4.0)
if(QUIC_AVAILABLE)
    target_compile_definitions(vortex PRIVATE VORTEX_QUIC=1)
    # Static archives (link whole-archive to avoid symbol stripping)
    target_link_libraries(vortex
        -Wl,--whole-archive
        ${NGTCP2_BUILD_DIR}/crypto/ossl/libngtcp2_crypto_ossl.a
        -Wl,--no-whole-archive
        ${NGTCP2_BUILD_DIR}/lib/libngtcp2.a
        ${NGHTTP3_BUILD_DIR}/lib/libnghttp3.a
    )
endif()

# Define build phase for conditional compilation
target_compile_definitions(vortex PRIVATE VORTEX_PHASE=7)

# ---- Tests ----
add_subdirectory(tests)

# ---- Fuzzer targets (clang only, -DVORTEX_FUZZ=ON) ----
if(VORTEX_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "VORTEX_FUZZ requires clang (libFuzzer is clang-only)")
    endif()
    add_subdirectory(fuzz)
endif()

# ---- Install ----
install(TARGETS vortex RUNTIME DESTINATION bin)
install(FILES "${CMAKE_BINARY_DIR}/vortex_xdp.bpf.o" DESTINATION share/vortex)
install(FILES config/vortex.example.yaml DESTINATION etc/vortex)

# ---- Summary ----
message(STATUS "")
message(STATUS "=== vortex build configuration ===")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  C compiler:     ${CMAKE_C_COMPILER}")
message(STATUS "  -march:         ${VORTEX_MARCH}")
message(STATUS "  libbpf:         ${LIBBPF_VERSION}")
message(STATUS "  liburing:       ${LIBURING_VERSION}")
message(STATUS "  libyaml:        ${YAML_VERSION}")
message(STATUS "  picotls (TLS):  ${PICOTLS_AVAILABLE}")
message(STATUS "  nghttp2 (H2):   ${NGHTTP2_FOUND}")
message(STATUS "  BPF compiler:   ${CLANG_BPF}")
message(STATUS "===================================")
message(STATUS "")

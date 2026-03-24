cmake_minimum_required(VERSION 3.20)
project(vortex C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---- Build type flags ----
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(CMAKE_C_FLAGS_RELEASE        "-O3 -march=znver3 -mtune=znver3 -DNDEBUG -flto")
set(CMAKE_C_FLAGS_DEBUG          "-O0 -g3 -fsanitize=address,undefined -DVORTEX_DEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")

# Common warnings
add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-stringop-truncation)

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

# ---- OpenSSL 4.0 (required for Phase 3+) ----
set(OPENSSL_ROOT_DIR "/opt/openssl-4.0" CACHE PATH "OpenSSL 4.0 installation prefix")
if(EXISTS "${OPENSSL_ROOT_DIR}/include/openssl/ssl.h")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libssl.so")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libcrypto.so")
    set(OPENSSL_AVAILABLE TRUE)
    message(STATUS "OpenSSL 4.0 found at ${OPENSSL_ROOT_DIR}")
else()
    set(OPENSSL_AVAILABLE FALSE)
    message(WARNING "OpenSSL 4.0 not found at ${OPENSSL_ROOT_DIR} — TLS phase will not compile")
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
    src/worker_proxy.c
    src/pool.c
    src/cache.c
    src/metrics.c
    src/dashboard.c
    src/simd.c
)

if(OPENSSL_AVAILABLE)
    list(APPEND VORTEX_SRCS src/tls.c)
    list(APPEND VORTEX_SRCS src/tls_pool.c)
    if(NGHTTP2_FOUND)
        list(APPEND VORTEX_SRCS src/worker_h2.c)
    endif()
    list(APPEND VORTEX_SRCS
        cert/static_file.c
        cert/acme_client.c
        cert/acme_http01.c
        cert/acme_dns01.c
        cert/dns_cloudflare.c
    )
endif()

# ---- HTTP/3 via ngtcp2 + nghttp3 (static, linked against OpenSSL 4.0) ----
set(NGTCP2_BUILD_DIR  "/tmp/ngtcp2-1.16-build" CACHE PATH "ngtcp2 build dir")
set(NGHTTP3_BUILD_DIR "/tmp/nghttp3-build"      CACHE PATH "nghttp3 build dir")
set(NGTCP2_SRC_DIR    "/tmp/ngtcp2-1.16.0"      CACHE PATH "ngtcp2 source dir")
set(NGHTTP3_SRC_DIR   "/tmp/nghttp3-1.8.0"      CACHE PATH "nghttp3 source dir")

if(OPENSSL_AVAILABLE AND
   EXISTS "${NGTCP2_BUILD_DIR}/lib/libngtcp2.a" AND
   EXISTS "${NGTCP2_BUILD_DIR}/crypto/ossl/libngtcp2_crypto_ossl.a" AND
   EXISTS "${NGHTTP3_BUILD_DIR}/lib/libnghttp3.a")
    set(QUIC_AVAILABLE TRUE)
    list(APPEND VORTEX_SRCS src/quic.c)
    message(STATUS "HTTP/3 (ngtcp2+nghttp3): enabled")
else()
    set(QUIC_AVAILABLE FALSE)
    message(STATUS "HTTP/3: disabled (build ngtcp2/nghttp3 first)")
endif()

add_executable(vortex ${VORTEX_SRCS})
add_dependencies(vortex bpf_prog)

target_include_directories(vortex PRIVATE
    ${CMAKE_SOURCE_DIR}/include
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

# TLS support via OpenSSL 4.0
if(OPENSSL_AVAILABLE)
    target_compile_definitions(vortex PRIVATE VORTEX_PHASE_TLS=1)
    target_include_directories(vortex PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(vortex ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
    target_link_directories(vortex PRIVATE "${OPENSSL_ROOT_DIR}/lib64")
    # Embed rpath so the binary finds the right libssl at runtime.
    # BUILD_RPATH points to the local build tree; INSTALL_RPATH points to
    # the location used in the installed .deb package (/usr/lib/vortex).
    set_target_properties(vortex PROPERTIES
        BUILD_RPATH "${OPENSSL_ROOT_DIR}/lib64"
        INSTALL_RPATH "/usr/lib/vortex"
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

# ---- Tests (Phase 1: config + log) ----
add_subdirectory(tests EXCLUDE_FROM_ALL)

# ---- Install ----
install(TARGETS vortex RUNTIME DESTINATION bin)
install(FILES "${CMAKE_BINARY_DIR}/vortex_xdp.bpf.o" DESTINATION share/vortex)
install(FILES config/vortex.example.yaml DESTINATION etc/vortex)

# ---- Summary ----
message(STATUS "")
message(STATUS "=== vortex build configuration ===")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  C compiler:     ${CMAKE_C_COMPILER}")
message(STATUS "  libbpf:         ${LIBBPF_VERSION}")
message(STATUS "  liburing:       ${LIBURING_VERSION}")
message(STATUS "  libyaml:        ${YAML_VERSION}")
message(STATUS "  OpenSSL 4.0:    ${OPENSSL_AVAILABLE}")
message(STATUS "  nghttp2 (H2):   ${NGHTTP2_FOUND}")
message(STATUS "  BPF compiler:   ${CLANG_BPF}")
message(STATUS "===================================")
message(STATUS "")

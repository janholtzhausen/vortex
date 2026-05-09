cmake_minimum_required(VERSION 3.20)

# Phase 1 tests: config parsing and logging

add_executable(test_config
    test_config.c
    ../src/config.c
    ../src/auth.c
    ../src/log.c
)
target_include_directories(test_config PRIVATE
    ../include
    ../src
    ../bpf
    ${YAML_INCLUDE_DIRS}
)
if(PICOTLS_AVAILABLE)
    target_compile_definitions(test_config PRIVATE VORTEX_PHASE_TLS=1)
    target_include_directories(test_config PRIVATE
        ${PICOTLS_SRC_DIR}/include
        ${PICOTLS_SRC_DIR}/deps/micro-ecc
    )
    target_link_libraries(test_config
        ${PICOTLS_BUILD_DIR}/libpicotls-minicrypto.a
        ${PICOTLS_BUILD_DIR}/libpicotls-core.a
    )
endif()
target_link_libraries(test_config ${YAML_LIBRARIES} pthread)
target_link_directories(test_config PRIVATE ${YAML_LIBRARY_DIRS})

add_executable(test_log
    test_log.c
    ../src/log.c
)
target_include_directories(test_log PRIVATE
    ../include
    ../src
)
target_link_libraries(test_log pthread)

add_executable(test_cache
    test_cache.c
    ../src/cache.c
    ../src/log.c
    ../src/chunked.c
    ../src/simd.c
)
target_include_directories(test_cache PRIVATE
    ../include
    ../src
)
if(PICOTLS_AVAILABLE)
    target_compile_definitions(test_cache PRIVATE VORTEX_PHASE_TLS=1)
    target_include_directories(test_cache PRIVATE
        ${PICOTLS_SRC_DIR}/include
        ${PICOTLS_SRC_DIR}/deps/micro-ecc
    )
    target_link_libraries(test_cache
        ${PICOTLS_BUILD_DIR}/libpicotls-minicrypto.a
        ${PICOTLS_BUILD_DIR}/libpicotls-core.a
    )
endif()
target_link_libraries(test_cache pthread)

add_executable(test_auth
    test_auth.c
    ../src/auth.c
)
target_include_directories(test_auth PRIVATE
    ../include
    ../src
)
if(PICOTLS_AVAILABLE)
    target_compile_definitions(test_auth PRIVATE VORTEX_PHASE_TLS=1)
    target_include_directories(test_auth PRIVATE
        ${PICOTLS_SRC_DIR}/include
        ${PICOTLS_SRC_DIR}/deps/micro-ecc
    )
    target_link_libraries(test_auth
        ${PICOTLS_BUILD_DIR}/libpicotls-minicrypto.a
        ${PICOTLS_BUILD_DIR}/libpicotls-core.a
    )
endif()
target_link_libraries(test_auth pthread)

add_executable(test_router
    test_router.c
    ../src/router.c
    ../src/config.c
    ../src/auth.c
    ../src/log.c
)
target_include_directories(test_router PRIVATE
    ../include
    ../src
    ../bpf
    ${YAML_INCLUDE_DIRS}
)
target_link_libraries(test_router ${YAML_LIBRARIES} pthread)
target_link_directories(test_router PRIVATE ${YAML_LIBRARY_DIRS})

add_executable(test_circuit_breaker
    test_circuit_breaker.c
    ../src/router.c
    ../src/log.c
)
target_include_directories(test_circuit_breaker PRIVATE ../include ../src)
target_link_libraries(test_circuit_breaker pthread)

add_executable(test_config_reload
    test_config_reload.c
    ../src/config.c
    ../src/auth.c
    ../src/log.c
)
target_include_directories(test_config_reload PRIVATE ../include ../src ../bpf ${YAML_INCLUDE_DIRS})
target_link_libraries(test_config_reload ${YAML_LIBRARIES} pthread)
target_link_directories(test_config_reload PRIVATE ${YAML_LIBRARY_DIRS})

add_test(NAME test_config         COMMAND $<TARGET_FILE:test_config>)
add_test(NAME test_log            COMMAND $<TARGET_FILE:test_log>)
add_test(NAME test_cache          COMMAND $<TARGET_FILE:test_cache>)
add_test(NAME test_auth           COMMAND $<TARGET_FILE:test_auth>)
add_test(NAME test_router         COMMAND $<TARGET_FILE:test_router>)
add_test(NAME test_circuit_breaker COMMAND $<TARGET_FILE:test_circuit_breaker>)
add_test(NAME test_config_reload  COMMAND $<TARGET_FILE:test_config_reload>)

# kTLS API unit test (no kernel support required)
if(PICOTLS_AVAILABLE)
    add_executable(test_ktls_api
        test_ktls_api.c
    )
    target_compile_definitions(test_ktls_api PRIVATE VORTEX_PHASE_TLS=1)
    target_include_directories(test_ktls_api PRIVATE
        ../include
        ../src
        ${PICOTLS_SRC_DIR}/include
        ${PICOTLS_SRC_DIR}/deps/micro-ecc
    )
    target_link_libraries(test_ktls_api
        ${PICOTLS_BUILD_DIR}/libpicotls-minicrypto.a
        ${PICOTLS_BUILD_DIR}/libpicotls-core.a
        pthread
    )
    add_test(NAME test_ktls_api COMMAND $<TARGET_FILE:test_ktls_api>)
endif()

# kTLS shell integration tests (require kTLS kernel module + root)
# Enable with: cmake -DVORTEX_KTLS_TESTS=ON
option(VORTEX_KTLS_TESTS "Enable kTLS integration shell tests (requires root + kTLS module)" OFF)
if(VORTEX_KTLS_TESTS)
    set(KTLS_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ktls)
    foreach(t
        test_ktls_http1_basic
        test_ktls_http1_early_data_same_segment
        test_ktls_tx_setsockopt_failure
        test_ktls_unsupported_cipher
        test_ktls_wrong_sni
        test_ktls_metrics
        test_ktls_many_short_connections
        test_ktls_large_response
    )
        add_test(NAME ${t}
            COMMAND ${KTLS_TEST_DIR}/${t}.sh
            WORKING_DIRECTORY ${KTLS_TEST_DIR})
        set_tests_properties(${t} PROPERTIES
            SKIP_RETURN_CODE 77
            LABELS ktls_shell
            ENVIRONMENT "VORTEX_BIN=$<TARGET_FILE:vortex>;VORTEX_CFG=/tmp/${t}.yaml")
    endforeach()
endif()

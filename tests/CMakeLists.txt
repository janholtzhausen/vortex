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
if(OPENSSL_AVAILABLE)
    target_compile_definitions(test_config PRIVATE VORTEX_PHASE_TLS=1)
    target_include_directories(test_config PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(test_config ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
    target_link_directories(test_config PRIVATE "${OPENSSL_ROOT_DIR}/lib64")
endif()
target_link_libraries(test_config ${YAML_LIBRARIES} pthread)
target_link_directories(test_config PRIVATE ${YAML_LIBRARY_DIRS})

add_executable(test_log
    test_log.c
    ../src/log.c
)
target_include_directories(test_log PRIVATE ../src)
target_link_libraries(test_log pthread)

add_executable(test_cache
    test_cache.c
    ../src/cache.c
    ../src/log.c
)
target_include_directories(test_cache PRIVATE ../src)
target_link_libraries(test_cache pthread)

enable_testing()
add_test(NAME test_config COMMAND test_config)
add_test(NAME test_log    COMMAND test_log)
add_test(NAME test_cache  COMMAND test_cache)

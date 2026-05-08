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

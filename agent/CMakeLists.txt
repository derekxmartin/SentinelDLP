cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# vcpkg toolchain (must be set before project())
# ---------------------------------------------------------------------------
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "vcpkg toolchain file")
endif()

project(AkesoDLPAgent
    VERSION 0.1.0
    DESCRIPTION "AkesoDLP Endpoint Agent"
    LANGUAGES CXX C
)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# MSVC-specific flags
if(MSVC)
    add_compile_options(
        /W4         # Warning level 4
        /WX         # Warnings as errors
        /MP         # Multi-processor compilation
        /permissive-  # Strict conformance
        /utf-8      # UTF-8 source and execution
        /Zc:__cplusplus  # Correct __cplusplus macro
    )

    # Debug-specific
    add_compile_options($<$<CONFIG:Debug>:/Zi>)       # Full debug info
    add_compile_options($<$<CONFIG:Debug>:/Od>)       # No optimization
    add_compile_options($<$<CONFIG:Debug>:/RTC1>)     # Runtime checks

    # Release-specific
    add_compile_options($<$<CONFIG:Release>:/O2>)     # Max speed optimization
    add_compile_options($<$<CONFIG:Release>:/GL>)     # Whole program optimization
    add_compile_options($<$<CONFIG:Release>:/Gy>)     # Function-level linking

    # Link-time code generation for Release
    add_link_options($<$<CONFIG:Release>:/LTCG>)
    add_link_options($<$<CONFIG:Release>:/OPT:REF>)   # Remove unreferenced code
    add_link_options($<$<CONFIG:Release>:/OPT:ICF>)   # COMDAT folding
endif()

# Platform definitions
add_compile_definitions(
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_DRIVER "Build minifilter driver (requires WDK)" OFF)

# ---------------------------------------------------------------------------
# Dependencies (via vcpkg)
# ---------------------------------------------------------------------------

# gRPC + Protobuf
find_package(gRPC CONFIG QUIET)
find_package(Protobuf CONFIG QUIET)

# Hyperscan (Intel regex engine)
find_package(unofficial-hyperscan CONFIG QUIET)
if(NOT unofficial-hyperscan_FOUND)
    # vcpkg installs Hyperscan without CMake config; find manually
    find_path(HYPERSCAN_INCLUDE_DIR hs/hs.h)
    find_library(HYPERSCAN_LIB hs)
    if(HYPERSCAN_INCLUDE_DIR AND HYPERSCAN_LIB)
        set(HYPERSCAN_FOUND TRUE)
        add_library(hyperscan::hs UNKNOWN IMPORTED)
        set_target_properties(hyperscan::hs PROPERTIES
            IMPORTED_LOCATION "${HYPERSCAN_LIB}"
            INTERFACE_INCLUDE_DIRECTORIES "${HYPERSCAN_INCLUDE_DIR}"
        )
    endif()
endif()

# SQLite3
find_package(unofficial-sqlite3 CONFIG QUIET)

# libcurl
find_package(CURL CONFIG QUIET)

# yaml-cpp
find_package(yaml-cpp CONFIG QUIET)

# zlib (compression, used by content extractor)
find_package(ZLIB QUIET)

# spdlog (structured logging)
find_package(spdlog CONFIG QUIET)

# Report dependency status
message(STATUS "--- Dependency Status ---")
message(STATUS "  gRPC:       ${gRPC_FOUND}")
message(STATUS "  Protobuf:   ${Protobuf_FOUND}")
if(unofficial-hyperscan_FOUND OR HYPERSCAN_FOUND)
    set(HAS_HYPERSCAN_AVAILABLE TRUE)
else()
    set(HAS_HYPERSCAN_AVAILABLE FALSE)
endif()
message(STATUS "  Hyperscan:  ${HAS_HYPERSCAN_AVAILABLE}")
message(STATUS "  SQLite3:    ${unofficial-sqlite3_FOUND}")
message(STATUS "  CURL:       ${CURL_FOUND}")
message(STATUS "  yaml-cpp:   ${yaml-cpp_FOUND}")
message(STATUS "  spdlog:     ${spdlog_FOUND}")
message(STATUS "  ZLIB:       ${ZLIB_FOUND}")
message(STATUS "-------------------------")

# ---------------------------------------------------------------------------
# Agent executable
# ---------------------------------------------------------------------------
add_executable(akeso-dlp-agent
    src/main.cpp
    src/config.cpp
    src/agent_service.cpp
    src/grpc_client.cpp
    src/policy_cache.cpp
    src/incident_queue.cpp
    src/detection/hs_regex_analyzer.cpp
    src/detection/keyword_analyzer.cpp
    src/detection/validators.cpp
    src/detection/file_type_detector.cpp
    src/detection/content_extractor.cpp
    src/detection/policy_evaluator.cpp
    src/detection/pipeline.cpp
    src/response/block_action.cpp
    src/response/notification.cpp
    src/driver_comm.cpp
)

target_include_directories(akeso-dlp-agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link available dependencies
if(spdlog_FOUND)
    target_link_libraries(akeso-dlp-agent PRIVATE spdlog::spdlog)
    target_compile_definitions(akeso-dlp-agent PRIVATE HAS_SPDLOG)
endif()

if(yaml-cpp_FOUND)
    target_link_libraries(akeso-dlp-agent PRIVATE yaml-cpp::yaml-cpp)
    target_compile_definitions(akeso-dlp-agent PRIVATE HAS_YAML_CPP)
endif()

if(gRPC_FOUND)
    target_link_libraries(akeso-dlp-agent PRIVATE
        gRPC::grpc++
        protobuf::libprotobuf
    )
    target_compile_definitions(akeso-dlp-agent PRIVATE HAS_GRPC)
endif()

if(unofficial-hyperscan_FOUND)
    target_link_libraries(akeso-dlp-agent PRIVATE unofficial::hyperscan::hyperscan)
    target_compile_definitions(akeso-dlp-agent PRIVATE HAS_HYPERSCAN)
elseif(HYPERSCAN_FOUND)
    target_link_libraries(akeso-dlp-agent PRIVATE hyperscan::hs)
    target_compile_definitions(akeso-dlp-agent PRIVATE HAS_HYPERSCAN)
endif()

if(unofficial-sqlite3_FOUND)
    target_link_libraries(akeso-dlp-agent PRIVATE unofficial::sqlite3::sqlite3)
    target_compile_definitions(akeso-dlp-agent PRIVATE HAS_SQLITE3)
endif()

if(CURL_FOUND)
    target_link_libraries(akeso-dlp-agent PRIVATE CURL::libcurl)
    target_compile_definitions(akeso-dlp-agent PRIVATE HAS_CURL)
endif()

if(ZLIB_FOUND)
    target_link_libraries(akeso-dlp-agent PRIVATE ZLIB::ZLIB)
    target_compile_definitions(akeso-dlp-agent PRIVATE HAS_ZLIB)
endif()

# Windows-specific libraries
if(WIN32)
    target_link_libraries(akeso-dlp-agent PRIVATE
        advapi32    # Service Control Manager
        bcrypt      # SHA-256 hashing (CNG)
        fltlib      # Minifilter user-mode API
        ws2_32      # Winsock
    )
endif()

# ---------------------------------------------------------------------------
# Protobuf/gRPC code generation
# ---------------------------------------------------------------------------
if(gRPC_FOUND AND Protobuf_FOUND)
    set(PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../proto")
    set(PROTO_FILES "${PROTO_DIR}/akesodlp.proto")
    set(PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/proto")

    file(MAKE_DIRECTORY ${PROTO_OUT_DIR})

    # Find protoc and grpc_cpp_plugin
    find_program(_PROTOC protoc HINTS ${Protobuf_PROTOC_EXECUTABLE})
    find_program(_GRPC_CPP_PLUGIN grpc_cpp_plugin)

    if(_PROTOC AND _GRPC_CPP_PLUGIN AND EXISTS "${PROTO_FILES}")
        # Generate protobuf sources
        add_custom_command(
            OUTPUT
                "${PROTO_OUT_DIR}/akesodlp.pb.h"
                "${PROTO_OUT_DIR}/akesodlp.pb.cc"
                "${PROTO_OUT_DIR}/akesodlp.grpc.pb.h"
                "${PROTO_OUT_DIR}/akesodlp.grpc.pb.cc"
            COMMAND ${_PROTOC}
                --proto_path=${PROTO_DIR}
                --proto_path=${Protobuf_INCLUDE_DIR}
                --cpp_out=${PROTO_OUT_DIR}
                --grpc_out=${PROTO_OUT_DIR}
                --plugin=protoc-gen-grpc=${_GRPC_CPP_PLUGIN}
                ${PROTO_FILES}
            DEPENDS ${PROTO_FILES}
            COMMENT "Generating C++ protobuf/gRPC stubs"
        )

        # Add generated sources to agent (suppress warnings on generated code)
        set_source_files_properties(
            "${PROTO_OUT_DIR}/akesodlp.pb.cc"
            "${PROTO_OUT_DIR}/akesodlp.grpc.pb.cc"
            PROPERTIES COMPILE_FLAGS "/W0"
        )
        target_sources(akeso-dlp-agent PRIVATE
            "${PROTO_OUT_DIR}/akesodlp.pb.cc"
            "${PROTO_OUT_DIR}/akesodlp.grpc.pb.cc"
        )
        target_include_directories(akeso-dlp-agent PRIVATE ${PROTO_OUT_DIR})

        message(STATUS "Protobuf/gRPC code generation configured")
    else()
        message(STATUS "Protobuf/gRPC codegen skipped (protoc or proto file not found)")
    endif()
endif()

# ---------------------------------------------------------------------------
# Driver (conditional, requires WDK)
# ---------------------------------------------------------------------------
if(BUILD_DRIVER)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    find_package(WDK)

    if(WDK_FOUND)
        add_subdirectory(driver)
    else()
        message(WARNING "BUILD_DRIVER=ON but WDK not found. Skipping driver build.")
    endif()
endif()

# ---------------------------------------------------------------------------
# Tests (GoogleTest)
# ---------------------------------------------------------------------------
if(BUILD_TESTS)
    find_package(GTest CONFIG QUIET)

    if(GTest_FOUND)
        enable_testing()

        # Config tests
        add_executable(test_config
            tests/test_config.cpp
            src/config.cpp
        )
        target_include_directories(test_config PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_config PRIVATE
            GTest::gtest_main
            yaml-cpp::yaml-cpp
        )
        if(spdlog_FOUND)
            target_link_libraries(test_config PRIVATE spdlog::spdlog)
            target_compile_definitions(test_config PRIVATE HAS_SPDLOG)
        endif()
        add_test(NAME ConfigTests COMMAND test_config)

        # PolicyCache tests
        add_executable(test_policy_cache
            tests/test_policy_cache.cpp
            src/policy_cache.cpp
        )
        target_include_directories(test_policy_cache PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_BINARY_DIR}/proto
        )
        target_link_libraries(test_policy_cache PRIVATE
            GTest::gtest_main
            unofficial::sqlite3::sqlite3
            protobuf::libprotobuf
        )
        if(spdlog_FOUND)
            target_link_libraries(test_policy_cache PRIVATE spdlog::spdlog)
            target_compile_definitions(test_policy_cache PRIVATE HAS_SPDLOG)
        endif()
        # Suppress protobuf generated code warnings
        target_compile_options(test_policy_cache PRIVATE /wd4267)
        # Depend on proto generation
        target_sources(test_policy_cache PRIVATE
            "${PROTO_OUT_DIR}/akesodlp.pb.cc"
        )
        set_source_files_properties(
            "${PROTO_OUT_DIR}/akesodlp.pb.cc"
            PROPERTIES COMPILE_FLAGS "/W0"
        )
        add_test(NAME PolicyCacheTests COMMAND test_policy_cache)

        # IncidentQueue tests
        add_executable(test_incident_queue
            tests/test_incident_queue.cpp
            src/incident_queue.cpp
        )
        target_include_directories(test_incident_queue PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_incident_queue PRIVATE
            GTest::gtest_main
            unofficial::sqlite3::sqlite3
        )
        if(spdlog_FOUND)
            target_link_libraries(test_incident_queue PRIVATE spdlog::spdlog)
            target_compile_definitions(test_incident_queue PRIVATE HAS_SPDLOG)
        endif()
        if(WIN32)
            target_link_libraries(test_incident_queue PRIVATE bcrypt)
        endif()
        add_test(NAME IncidentQueueTests COMMAND test_incident_queue)

        # HsRegexAnalyzer tests
        if(unofficial-hyperscan_FOUND OR HYPERSCAN_FOUND)
            add_executable(test_hs_regex_analyzer
                tests/test_hs_regex_analyzer.cpp
                src/detection/hs_regex_analyzer.cpp
            )
            target_include_directories(test_hs_regex_analyzer PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/include
            )
            if(unofficial-hyperscan_FOUND)
                target_link_libraries(test_hs_regex_analyzer PRIVATE
                    GTest::gtest_main
                    unofficial::hyperscan::hyperscan
                )
            else()
                target_link_libraries(test_hs_regex_analyzer PRIVATE
                    GTest::gtest_main
                    hyperscan::hs
                )
            endif()
            if(spdlog_FOUND)
                target_link_libraries(test_hs_regex_analyzer PRIVATE spdlog::spdlog)
                target_compile_definitions(test_hs_regex_analyzer PRIVATE HAS_SPDLOG)
            endif()
            target_compile_definitions(test_hs_regex_analyzer PRIVATE HAS_HYPERSCAN)
            add_test(NAME HsRegexAnalyzerTests COMMAND test_hs_regex_analyzer)
        endif()

        # KeywordAnalyzer tests
        add_executable(test_keyword_analyzer
            tests/test_keyword_analyzer.cpp
            src/detection/keyword_analyzer.cpp
        )
        target_include_directories(test_keyword_analyzer PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_keyword_analyzer PRIVATE
            GTest::gtest_main
        )
        if(spdlog_FOUND)
            target_link_libraries(test_keyword_analyzer PRIVATE spdlog::spdlog)
            target_compile_definitions(test_keyword_analyzer PRIVATE HAS_SPDLOG)
        endif()
        add_test(NAME KeywordAnalyzerTests COMMAND test_keyword_analyzer)

        # Validators tests
        add_executable(test_validators
            tests/test_validators.cpp
            src/detection/validators.cpp
        )
        target_include_directories(test_validators PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_validators PRIVATE
            GTest::gtest_main
        )
        if(spdlog_FOUND)
            target_link_libraries(test_validators PRIVATE spdlog::spdlog)
            target_compile_definitions(test_validators PRIVATE HAS_SPDLOG)
        endif()
        add_test(NAME ValidatorTests COMMAND test_validators)

        # FileTypeDetector tests
        add_executable(test_file_type_detector
            tests/test_file_type_detector.cpp
            src/detection/file_type_detector.cpp
        )
        target_include_directories(test_file_type_detector PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_file_type_detector PRIVATE
            GTest::gtest_main
        )
        if(spdlog_FOUND)
            target_link_libraries(test_file_type_detector PRIVATE spdlog::spdlog)
            target_compile_definitions(test_file_type_detector PRIVATE HAS_SPDLOG)
        endif()
        add_test(NAME FileTypeDetectorTests COMMAND test_file_type_detector)

        # ContentExtractor tests
        add_executable(test_content_extractor
            tests/test_content_extractor.cpp
            src/detection/content_extractor.cpp
            src/detection/file_type_detector.cpp
        )
        target_include_directories(test_content_extractor PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_content_extractor PRIVATE
            GTest::gtest_main
            ZLIB::ZLIB
        )
        if(spdlog_FOUND)
            target_link_libraries(test_content_extractor PRIVATE spdlog::spdlog)
            target_compile_definitions(test_content_extractor PRIVATE HAS_SPDLOG)
        endif()
        add_test(NAME ContentExtractorTests COMMAND test_content_extractor)

        # PolicyEvaluator tests
        add_executable(test_policy_evaluator
            tests/test_policy_evaluator.cpp
            src/detection/policy_evaluator.cpp
        )
        target_include_directories(test_policy_evaluator PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_policy_evaluator PRIVATE
            GTest::gtest_main
        )
        if(spdlog_FOUND)
            target_link_libraries(test_policy_evaluator PRIVATE spdlog::spdlog)
            target_compile_definitions(test_policy_evaluator PRIVATE HAS_SPDLOG)
        endif()
        add_test(NAME PolicyEvaluatorTests COMMAND test_policy_evaluator)

        # DriverComm tests
        add_executable(test_driver_comm
            tests/test_driver_comm.cpp
            src/driver_comm.cpp
        )
        target_include_directories(test_driver_comm PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(test_driver_comm PRIVATE
            GTest::gtest_main
            fltlib
        )
        if(spdlog_FOUND)
            target_link_libraries(test_driver_comm PRIVATE spdlog::spdlog)
            target_compile_definitions(test_driver_comm PRIVATE HAS_SPDLOG)
        endif()
        add_test(NAME DriverCommTests COMMAND test_driver_comm)

        message(STATUS "Testing enabled (GoogleTest found)")
    else()
        message(STATUS "GoogleTest not found. Tests disabled.")
    endif()
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(TARGETS akeso-dlp-agent
    RUNTIME DESTINATION bin
)

install(FILES config/config.yaml.example
    DESTINATION etc/akeso-dlp
    RENAME config.yaml
)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "=== AkesoDLP Agent Build Configuration ===")
message(STATUS "  Version:     ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type:  ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler:    ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Build Tests: ${BUILD_TESTS}")
message(STATUS "  Build Driver: ${BUILD_DRIVER}")
message(STATUS "=============================================")
message(STATUS "")

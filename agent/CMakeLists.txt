cmake_minimum_required(VERSION 3.20)
project(SentinelDLPAgent VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Options ---
option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_DRIVER "Build minifilter driver (requires WDK)" OFF)

# --- Agent executable ---
add_executable(sentinel-dlp-agent
    src/main.cpp
)

target_include_directories(sentinel-dlp-agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# --- Driver (conditional, requires WDK) ---
if(BUILD_DRIVER)
    add_subdirectory(driver)
endif()

# --- Tests ---
if(BUILD_TESTS)
    enable_testing()
    # Tests will be added as source files are created
endif()

# --- Install ---
install(TARGETS sentinel-dlp-agent DESTINATION bin)

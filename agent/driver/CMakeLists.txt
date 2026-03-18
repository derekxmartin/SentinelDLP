# ---------------------------------------------------------------------------
# SentinelDLP Minifilter Driver
# ---------------------------------------------------------------------------
# This builds the kernel-mode minifilter driver (.sys) using WDK.
#
# NOTE: Kernel-mode drivers cannot be built with the standard CMake
# MSVC generator in the same way as user-mode code. This CMakeLists
# provides the source list and configuration for use with:
#   1. The WDK MSBuild integration (Visual Studio)
#   2. A separate WDK build environment
#
# For production builds, use the .vcxproj or the INF + WDK command line.
# ---------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.20)

set(DRIVER_NAME sentinel_dlp_filter)

# Source files
set(DRIVER_SOURCES
    sentinel_dlp_filter.c
    filter_comm.c
)

set(DRIVER_HEADERS
    sentinel_dlp_filter.h
)

# INF file
set(DRIVER_INF
    sentinel_dlp_filter.inf
)

# ---------------------------------------------------------------------------
# If WDK is available, try to build via wdk_add_driver
# (provided by FindWDK.cmake in parent project)
# ---------------------------------------------------------------------------
if(COMMAND wdk_add_driver)
    wdk_add_driver(${DRIVER_NAME}
        ${DRIVER_SOURCES}
        ${DRIVER_HEADERS}
    )

    target_compile_definitions(${DRIVER_NAME} PRIVATE
        SENTINEL_DLP_DRIVER
        POOL_NX_OPTIN=1
    )

    # Link against FltMgr (Filter Manager)
    target_link_libraries(${DRIVER_NAME}
        fltMgr
    )

    message(STATUS "Driver target '${DRIVER_NAME}' configured via WDK")

elseif(WDK_FOUND)
    # WDK found but no wdk_add_driver command — create a custom target
    # that invokes MSBuild with WDK integration
    message(STATUS "WDK found but wdk_add_driver not available.")
    message(STATUS "Use Visual Studio or 'msbuild' to build the driver.")
    message(STATUS "Driver sources: ${DRIVER_SOURCES}")

    # Create a custom target so the sources show up in the IDE
    add_custom_target(${DRIVER_NAME}_sources
        SOURCES ${DRIVER_SOURCES} ${DRIVER_HEADERS} ${DRIVER_INF}
    )

else()
    message(STATUS "WDK not found — driver build skipped.")
    message(STATUS "Install the Windows Driver Kit to build the minifilter.")

    # Still create a source-only target for IDE visibility
    add_custom_target(${DRIVER_NAME}_sources
        SOURCES ${DRIVER_SOURCES} ${DRIVER_HEADERS} ${DRIVER_INF}
    )
endif()

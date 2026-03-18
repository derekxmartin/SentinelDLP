# FindWDK.cmake — Locate the Windows Driver Kit (WDK)
#
# This module finds the WDK installation and sets up variables
# for building kernel-mode minifilter drivers.
#
# Output variables:
#   WDK_FOUND            — TRUE if WDK was found
#   WDK_ROOT             — Root directory of the WDK
#   WDK_VERSION          — WDK version string
#   WDK_INCLUDE_DIRS     — Include directories for kernel-mode headers
#   WDK_LIB_DIR          — Library directory for kernel-mode libs
#   WDK_BIN_DIR          — Binary directory (inf2cat, stampinf, etc.)
#   WDK_KMDF_INC_DIR     — KMDF framework include directory
#   WDK_KMDF_LIB_DIR     — KMDF framework library directory
#
# Functions:
#   wdk_add_driver(target sources...)  — Add a minifilter driver target
#

# Common WDK installation paths
set(_WDK_SEARCH_PATHS
    "$ENV{WDKContentRoot}"
    "C:/Program Files (x86)/Windows Kits/10"
    "C:/Program Files/Windows Kits/10"
)

# Find WDK root
set(WDK_FOUND FALSE)
set(WDK_ROOT "" CACHE PATH "Windows Driver Kit root directory")

if(NOT WDK_ROOT)
    foreach(_path ${_WDK_SEARCH_PATHS})
        if(EXISTS "${_path}/Include")
            set(WDK_ROOT "${_path}")
            break()
        endif()
    endforeach()
endif()

if(NOT WDK_ROOT OR NOT EXISTS "${WDK_ROOT}/Include")
    if(WDK_FIND_REQUIRED)
        message(FATAL_ERROR "Windows Driver Kit (WDK) not found. "
            "Set WDK_ROOT to the WDK installation directory or install the WDK.")
    else()
        message(STATUS "WDK not found (optional). Driver build will be skipped.")
        return()
    endif()
endif()

# Find the latest WDK version
file(GLOB _WDK_VERSIONS "${WDK_ROOT}/Include/*")
set(WDK_VERSION "")
foreach(_ver_path ${_WDK_VERSIONS})
    get_filename_component(_ver "${_ver_path}" NAME)
    if(_ver MATCHES "^10\\.")
        if("${_ver}" VERSION_GREATER "${WDK_VERSION}")
            set(WDK_VERSION "${_ver}")
        endif()
    endif()
endforeach()

if(NOT WDK_VERSION)
    message(WARNING "Could not determine WDK version in ${WDK_ROOT}/Include")
    return()
endif()

message(STATUS "Found WDK ${WDK_VERSION} at ${WDK_ROOT}")

# Platform architecture
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_WDK_ARCH "x64")
else()
    set(_WDK_ARCH "x86")
endif()

# Set output variables
set(WDK_FOUND TRUE)

set(WDK_INCLUDE_DIRS
    "${WDK_ROOT}/Include/${WDK_VERSION}/km"
    "${WDK_ROOT}/Include/${WDK_VERSION}/shared"
    "${WDK_ROOT}/Include/${WDK_VERSION}/km/crt"
)

set(WDK_LIB_DIR
    "${WDK_ROOT}/Lib/${WDK_VERSION}/km/${_WDK_ARCH}"
)

set(WDK_BIN_DIR
    "${WDK_ROOT}/bin/${WDK_VERSION}/${_WDK_ARCH}"
)

# KMDF (Kernel-Mode Driver Framework)
# Find the latest KMDF version
set(WDK_KMDF_VERSION "")
file(GLOB _KMDF_VERSIONS "${WDK_ROOT}/Include/wdf/kmdf/*")
foreach(_kmdf_path ${_KMDF_VERSIONS})
    get_filename_component(_kmdf_ver "${_kmdf_path}" NAME)
    if("${_kmdf_ver}" VERSION_GREATER "${WDK_KMDF_VERSION}")
        set(WDK_KMDF_VERSION "${_kmdf_ver}")
    endif()
endforeach()

if(WDK_KMDF_VERSION)
    set(WDK_KMDF_INC_DIR "${WDK_ROOT}/Include/wdf/kmdf/${WDK_KMDF_VERSION}")
    set(WDK_KMDF_LIB_DIR "${WDK_ROOT}/Lib/wdf/kmdf/${_WDK_ARCH}/${WDK_KMDF_VERSION}")
    message(STATUS "  KMDF version: ${WDK_KMDF_VERSION}")
endif()

# Mark as advanced
mark_as_advanced(WDK_ROOT WDK_VERSION)

# ---------------------------------------------------------------------------
# Function: wdk_add_driver
# ---------------------------------------------------------------------------
# Creates a kernel-mode driver target with proper compile/link flags.
#
# Usage:
#   wdk_add_driver(MyDriver
#       src/driver.c
#       src/comm.c
#   )
#
function(wdk_add_driver _target)
    set(_sources ${ARGN})

    add_library(${_target} SHARED ${_sources})

    # Kernel-mode compile definitions
    target_compile_definitions(${_target} PRIVATE
        _AMD64_
        _WIN64
        NTDDI_VERSION=0x0A000008   # Windows 10 2004+
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
        POOL_NX_OPTIN=1
        DEPRECATE_DDK_FUNCTIONS=1
    )

    # Include directories
    target_include_directories(${_target} PRIVATE
        ${WDK_INCLUDE_DIRS}
    )
    if(WDK_KMDF_INC_DIR)
        target_include_directories(${_target} PRIVATE
            ${WDK_KMDF_INC_DIR}
        )
    endif()

    # Kernel-mode compile flags (MSVC)
    target_compile_options(${_target} PRIVATE
        /kernel
        /GS-                # No buffer security check (kernel)
        /Gz                 # __stdcall calling convention
        /W4                 # Warning level 4
        /WX                 # Warnings as errors
        /Zp8                # 8-byte struct alignment
        /d1import_no_registry
        /d2AllowCompatibleILVersions
        /d2Zi+
    )

    # Linker flags
    set_target_properties(${_target} PROPERTIES
        SUFFIX ".sys"
        LINK_FLAGS "/DRIVER /SUBSYSTEM:NATIVE /ENTRY:FltDriverEntry /NODEFAULTLIB /MANIFEST:NO"
    )

    # Link kernel libraries
    target_link_directories(${_target} PRIVATE ${WDK_LIB_DIR})
    target_link_libraries(${_target} PRIVATE
        ntoskrnl
        hal
        fltMgr
        wmilib
        BufferOverflowFastFailK
    )

    if(WDK_KMDF_LIB_DIR)
        target_link_directories(${_target} PRIVATE ${WDK_KMDF_LIB_DIR})
        target_link_libraries(${_target} PRIVATE WdfDriverEntry WdfLdr)
    endif()

    message(STATUS "Added driver target: ${_target}")
endfunction()

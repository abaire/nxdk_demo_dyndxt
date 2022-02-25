cmake_minimum_required(VERSION 3.18)
project(demo_dyndxt)

set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)
set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")
set(CMAKE_SHARED_LIBRARY_SUFFIX_C ".dll")
set(CMAKE_SHARED_LIBRARY_SUFFIX_CXX ".dll")

set(CMAKE_VERBOSE_MAKEFILE TRUE)

set(CMAKE_CXX_STANDARD 17)
include(CMakePushCheckState)
set(_CMAKE_PROCESSING_LANGUAGE "C")
include(CheckSymbolExists)
include (ExternalProject)
include(FindPkgConfig)

set(CMAKE_CXX_FLAGS_DEBUG "-g -Og")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# Import the dynamic DXT loader, which provides some shared functions.
ExternalProject_Add(
        dyndxt_loader
        PREFIX ddxt
        GIT_REPOSITORY https://github.com/abaire/nxdk_dyndxt.git
        GIT_TAG origin/main
        CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        BUILD_BYPRODUCTS ddxt/lib/xbdm.lib ddxt/lib/dynamic_dxt_loader.lib
)
# The directory of header files for methods exported by the dynamic DXT loader.
ExternalProject_Get_Property(dyndxt_loader INSTALL_DIR)
set(dyndxt_lib_dir ${INSTALL_DIR}/lib)
set(dyndxt_include_dir ${INSTALL_DIR}/include)

# Pre-create the directory to pass CMake generator check.
file (MAKE_DIRECTORY ${dyndxt_include_dir})

# Import library containing various XBDM DLL exports.
add_library(xbdm_lib SHARED IMPORTED)
set_target_properties(
        xbdm_lib
        PROPERTIES
        IMPORTED_LOCATION ${dyndxt_lib_dir}/xbdm.lib
        INTERFACE_INCLUDE_DIRECTORIES ${dyndxt_include_dir}
)
add_dependencies(xbdm_lib dyndxt_loader)

# Import library containing functions exposed by the dynamic DXT loader.
add_library(ddxt_loader_lib SHARED IMPORTED)
add_dependencies(ddxt_loader_lib dyndxt_loader)
set_target_properties(
        ddxt_loader_lib
        PROPERTIES
        IMPORTED_LOCATION ${dyndxt_lib_dir}/dynamic_dxt_loader.lib
        INTERFACE_INCLUDE_DIRECTORIES ${dyndxt_include_dir}
)



set(TARGET demo_dyndxt)

add_library(
        ${TARGET}
        SHARED
        src/dxtmain.c
)
target_include_directories(
        ${TARGET}
        PRIVATE
        src
        ${NXDK_DIR}
        ${dyndxt_include_dir}
)
target_link_options(
        ${TARGET}
        PUBLIC
        -Wl,-machine:i386
        -B ${NXDK_DIR}/bin
        -Wl,-entry:DxtMain
        -Wl,-dynamicbase
        -Wl,-fixed:no
        -v
)
target_link_libraries(
        ${TARGET}
        PRIVATE
        ddxt_loader_lib
        xbdm_lib
)
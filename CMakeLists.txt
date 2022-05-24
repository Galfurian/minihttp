# -----------------------------------------------------------------------------
# @brief  : Root cmake file.
# @author : Enrico Fraccaroli
# @create : 03/01/2022
# @update : 03/01/2022
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Set the minimum CMake version, the project name and default build type.
# -----------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.1)

# Set the project name.
project(minihttp CXX)

# We need this in order to import external projects.
include(FetchContent)

# Extend the CMake module path.
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/")

# -----------------------------------------------------------------------------
# Add options.
# -----------------------------------------------------------------------------
option(STRICT_WARNINGS "Enable strict compiler warnings" ON)
option(WARNINGS_AS_ERRORS "Treat all warnings as errors" OFF)
option(BUILD_EXAMPLES "Build examples" OFF)

# -----------------------------------------------------------------------------
# DEPENDENCIES
# -----------------------------------------------------------------------------
find_package(mbedtls REQUIRED)

# -----------------------------------------------------------------------------
# LIBRARY
# -----------------------------------------------------------------------------
# Add the C++ library.
add_library(minihttp INTERFACE)
add_library(minihttp::minihttp ALIAS minihttp)
# Inlcude header directories.
target_include_directories(minihttp INTERFACE ${PROJECT_SOURCE_DIR}/include ${MBEDTLS_INCLUDE_DIRS})
# Link libraries.
target_link_libraries(minihttp INTERFACE mbedtls mbedx509 mbedcrypto)
if(WIN32)
    target_link_libraries(minihttp INTERFACE ws2_32)
endif()

# -----------------------------------------------------------------------------
# Set the compilation flags.
# -----------------------------------------------------------------------------
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # Disable warnings that suggest using MSVC-specific safe functions
    target_compile_definitions(minihttp INTERFACE _CRT_SECURE_NO_WARNINGS)
    if(WARNINGS_AS_ERRORS)
        target_compile_options(minihttp INTERFACE /WX)
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    if(WARNINGS_AS_ERRORS)
        target_compile_options(minihttp INTERFACE -Werror)
    endif()
endif()

if(STRICT_WARNINGS)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        # Mark system headers as external for MSVC explicitly
        # https://devblogs.microsoft.com/cppblog/broken-warnings-theory
        target_compile_options(minihttp INTERFACE /experimental:external)
        target_compile_options(minihttp INTERFACE /external:I ${CMAKE_BINARY_DIR})
        target_compile_options(minihttp INTERFACE /external:anglebrackets)
        target_compile_options(minihttp INTERFACE /external:W0)

        target_compile_options(minihttp INTERFACE /W4)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(minihttp INTERFACE -Wall -Wextra -Wconversion -pedantic)
    endif()
endif()

# -----------------------------------------------------------------------------
# DOCUMENTATION
# -----------------------------------------------------------------------------
find_package(Doxygen)
if(DOXYGEN_FOUND)
    message(STATUS "Retrieving `doxygen-awesome-css`...")
    FetchContent_Declare(
        doxygenawesome
        GIT_REPOSITORY https://github.com/jothepro/doxygen-awesome-css
        GIT_TAG 4cd62308d825fe0396d2f66ffbab45d0e247724c # 2.0.3
    )
    FetchContent_GetProperties(doxygenawesome)
    if(NOT doxygenawesome_POPULATED)
        FetchContent_MakeAvailable(doxygenawesome)
    endif()

    set(DOXYGEN_WARN_FORMAT "$file($line): $text")
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE README.md)
    set(DOXYGEN_GENERATE_TREEVIEW YES)
    set(DOXYGEN_HTML_HEADER ${doxygenawesome_SOURCE_DIR}/doxygen-custom/header.html)
    set(DOXYGEN_HTML_EXTRA_STYLESHEET ${doxygenawesome_SOURCE_DIR}/doxygen-awesome.css)
    set(DOXYGEN_HTML_EXTRA_FILES
        ${doxygenawesome_SOURCE_DIR}/doxygen-awesome-fragment-copy-button.js
        ${doxygenawesome_SOURCE_DIR}/doxygen-awesome-paragraph-link.js
        ${doxygenawesome_SOURCE_DIR}/doxygen-awesome-darkmode-toggle.js
    )
    doxygen_add_docs(minihttp_documentation
        include/minihttp.hpp
        README.md
    )
endif()

# -----------------------------------------------------------------------------
# Examples
# -----------------------------------------------------------------------------
if(BUILD_EXAMPLES)
    add_subdirectory(example)
endif()
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

# Extend the CMake module path.
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/")

# Set the default build type to Debug.
if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Setting build type to 'Debug' as none was specified.")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of build." FORCE)
endif()

# -----------------------------------------------------------------------------
# ENABLE FETCH CONTENT
# -----------------------------------------------------------------------------

# We need this in order to import external projects.
include(FetchContent)
# Hide fetchcontent variables.
mark_as_advanced(FORCE
    FETCHCONTENT_QUIET
    FETCHCONTENT_BASE_DIR
    FETCHCONTENT_FULLY_DISCONNECTED
    FETCHCONTENT_UPDATES_DISCONNECTED
)

# -----------------------------------------------------------------------------
# OPTIONS
# -----------------------------------------------------------------------------

option(${PROJECT_NAME}_STRICT_WARNINGS "Enable strict compiler warnings" ON)
option(${PROJECT_NAME}_WARNINGS_AS_ERRORS "Treat all warnings as errors" OFF)
option(${PROJECT_NAME}_BUILD_EXAMPLES "Build examples" OFF)

# -----------------------------------------------------------------------------
# DEPENDENCIES
# -----------------------------------------------------------------------------

# We need mbedtls.
find_package(mbedtls REQUIRED)

# We want doxygen for the documentation.
find_package(Doxygen)

# -----------------------------------------------------------------------------
# LIBRARY
# -----------------------------------------------------------------------------
# Add the C++ library.
add_library(${PROJECT_NAME} INTERFACE)
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
# Inlcude header directories.
target_include_directories(${PROJECT_NAME} INTERFACE ${PROJECT_SOURCE_DIR}/include ${MBEDTLS_INCLUDE_DIRS})
# Link libraries.
target_link_libraries(${PROJECT_NAME} INTERFACE mbedtls mbedx509 mbedcrypto)
if(WIN32)
    target_link_libraries(${PROJECT_NAME} INTERFACE ws2_32)
endif()

# -----------------------------------------------------------------------------
# Set the compilation flags.
# -----------------------------------------------------------------------------
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # Disable warnings that suggest using MSVC-specific safe functions
    target_compile_definitions(${PROJECT_NAME} INTERFACE _CRT_SECURE_NO_WARNINGS)
    if(${PROJECT_NAME}_WARNINGS_AS_ERRORS)
        target_compile_options(${PROJECT_NAME} INTERFACE /WX)
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    if(${PROJECT_NAME}_WARNINGS_AS_ERRORS)
        target_compile_options(${PROJECT_NAME} INTERFACE -Werror)
    endif()
endif()

if(${PROJECT_NAME}_STRICT_WARNINGS)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        # Mark system headers as external for MSVC explicitly
        # https://devblogs.microsoft.com/cppblog/broken-warnings-theory
        target_compile_options(${PROJECT_NAME} INTERFACE /experimental:external)
        target_compile_options(${PROJECT_NAME} INTERFACE /external:I ${CMAKE_BINARY_DIR})
        target_compile_options(${PROJECT_NAME} INTERFACE /external:anglebrackets)
        target_compile_options(${PROJECT_NAME} INTERFACE /external:W0)

        target_compile_options(${PROJECT_NAME} INTERFACE /W4)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${PROJECT_NAME} INTERFACE -Wall -Wextra -Wconversion -pedantic)
    endif()
endif()

# -----------------------------------------------------------------------------
# EXAMPLES
# -----------------------------------------------------------------------------

if(${PROJECT_NAME}_BUILD_EXAMPLES)
        
    # Retrieve the source.
    FetchContent_Declare(json
    GIT_REPOSITORY "https://github.com/Galfurian/json.git"
    GIT_TAG main
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
    )
    # Retrieve the properties related to the content.
    FetchContent_GetProperties(json)
    # If not populated, make the content available.
    if(NOT json_POPULATED)
    message(STATUS "Retrieving `json`...")
    # Ensures the named dependencies have been populated.
    FetchContent_MakeAvailable(json)
    # Hide fetchcontent variables, otherwise with ccmake it's a mess.
    mark_as_advanced(FORCE
        FETCHCONTENT_UPDATES_DISCONNECTED_JSON
        FETCHCONTENT_SOURCE_DIR_JSON
    )
    endif(NOT json_POPULATED)

    # = TARGETS ===============================================================

    add_executable(${PROJECT_NAME}_example ${PROJECT_SOURCE_DIR}/examples/example.cpp)
    target_link_libraries(${PROJECT_NAME}_example PUBLIC ${PROJECT_NAME})
    target_include_directories(${PROJECT_NAME}_example PUBLIC ${PROJECT_SOURCE_DIR}/include)
    
    add_executable(${PROJECT_NAME}_get_example ${PROJECT_SOURCE_DIR}/examples/get_example.cpp)
    target_link_libraries(${PROJECT_NAME}_get_example PUBLIC ${PROJECT_NAME})
    target_include_directories(${PROJECT_NAME}_get_example PUBLIC ${PROJECT_SOURCE_DIR}/include)
    
    add_executable(${PROJECT_NAME}_post_example ${PROJECT_SOURCE_DIR}/examples/post_example.cpp)
    target_link_libraries(${PROJECT_NAME}_post_example PUBLIC ${PROJECT_NAME} json)
    target_include_directories(${PROJECT_NAME}_post_example PUBLIC ${PROJECT_SOURCE_DIR}/include ${json_SOURCE_DIR}/include)

endif()

# -----------------------------------------------------------------------------
# DOCUMENTATION
# -----------------------------------------------------------------------------
if(DOXYGEN_FOUND)

    # Record the options that describe how to populate the specified content.
    FetchContent_Declare(
        doxygenawesome
        GIT_REPOSITORY https://github.com/jothepro/doxygen-awesome-css
        GIT_TAG 4cd62308d825fe0396d2f66ffbab45d0e247724c # 2.0.3
    )
    # Retrieve the properties related to the content.
    FetchContent_GetProperties(doxygenawesome)
    # If not populated, make the content available.
    if(NOT doxygenawesome_POPULATED)
        message(STATUS "Retrieving `doxygen-awesome-css`...")
        # Ensures the named dependencies have been populated.
        FetchContent_MakeAvailable(doxygenawesome)
        # Hide fetchcontent variables, otherwise with ccmake it's a mess.
        mark_as_advanced(FORCE
            FETCHCONTENT_UPDATES_DISCONNECTED_DOXYGENAWESOME
            FETCHCONTENT_SOURCE_DIR_DOXYGENAWESOME
        )
    endif()

    # = CUSTOMIZATION =========================================================
    set(DOXYGEN_WARN_FORMAT "$file:$line: $text")
    set(DOXYGEN_PROJECT_NAME ${PROJECT_NAME})
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE ${PROJECT_SOURCE_DIR}/README.md)
    set(DOXYGEN_SHOW_INCLUDE_FILES NO)
    set(DOXYGEN_GENERATE_TREEVIEW YES)
    set(DOXYGEN_HTML_HEADER ${doxygenawesome_SOURCE_DIR}/doxygen-custom/header.html)
    set(DOXYGEN_HTML_EXTRA_STYLESHEET ${doxygenawesome_SOURCE_DIR}/doxygen-awesome.css)
    set(DOXYGEN_HTML_EXTRA_FILES
        ${doxygenawesome_SOURCE_DIR}/doxygen-awesome-fragment-copy-button.js
        ${doxygenawesome_SOURCE_DIR}/doxygen-awesome-paragraph-link.js
        ${doxygenawesome_SOURCE_DIR}/doxygen-awesome-darkmode-toggle.js
    )
    doxygen_add_docs(
        ${PROJECT_NAME}_documentation
        ${PROJECT_SOURCE_DIR}/README.md
        ${PROJECT_SOURCE_DIR}/include/minihttp/minihttp.hpp
    )
endif()

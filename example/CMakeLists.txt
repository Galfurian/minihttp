# -----------------------------------------------------------------------------
# DEPENDENCIES
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# EXAMPLES
# -----------------------------------------------------------------------------

add_executable(minihttp_example example.cpp)
target_link_libraries(minihttp_example PUBLIC minihttp)
target_include_directories(minihttp_example PUBLIC ${PROJECT_SOURCE_DIR}/include)

add_executable(minihttp_get_example get_example.cpp)
target_link_libraries(minihttp_get_example PUBLIC minihttp)
target_include_directories(minihttp_get_example PUBLIC ${PROJECT_SOURCE_DIR}/include)

add_executable(minihttp_post_example post_example.cpp)
target_link_libraries(minihttp_post_example PUBLIC minihttp json)
target_include_directories(minihttp_post_example PUBLIC ${PROJECT_SOURCE_DIR}/include ${json_SOURCE_DIR}/include)

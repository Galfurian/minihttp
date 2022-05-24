# -----------------------------------------------------------------------------
# External projects.
# -----------------------------------------------------------------------------
message(STATUS "Retrieving `json`...")
FetchContent_Declare(
    json
    GIT_REPOSITORY "https://github.com/Galfurian/json.git"
    GIT_TAG        main
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)
FetchContent_GetProperties(json)
if(NOT json_POPULATED)
    FetchContent_MakeAvailable(json)
endif()

add_executable(minihttp_example example.cpp)
target_link_libraries(minihttp_example PRIVATE minihttp)
target_include_directories(minihttp_example PRIVATE ${PROJECT_SOURCE_DIR}/include)

add_executable(minihttp_get_example get_example.cpp)
target_link_libraries(minihttp_get_example PRIVATE minihttp)
target_include_directories(minihttp_get_example PRIVATE ${PROJECT_SOURCE_DIR}/include)

add_executable(minihttp_post_example post_example.cpp)
target_link_libraries(minihttp_post_example PRIVATE minihttp json)
target_include_directories(minihttp_post_example PRIVATE ${PROJECT_SOURCE_DIR}/include ${json_SOURCE_DIR}/include)
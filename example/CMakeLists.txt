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

add_executable(${PROJECT_NAME}_example example.cpp)
target_link_libraries(${PROJECT_NAME}_example PRIVATE minihttp)
target_include_directories(${PROJECT_NAME}_example PRIVATE ${PROJECT_SOURCE_DIR}/include)

add_executable(${PROJECT_NAME}_get_example get_example.cpp)
target_link_libraries(${PROJECT_NAME}_get_example PRIVATE minihttp)
target_include_directories(${PROJECT_NAME}_get_example PRIVATE ${PROJECT_SOURCE_DIR}/include)

add_executable(${PROJECT_NAME}_post_example post_example.cpp)
target_link_libraries(${PROJECT_NAME}_post_example PRIVATE minihttp json)
target_include_directories(${PROJECT_NAME}_post_example PRIVATE ${PROJECT_SOURCE_DIR}/include ${json_SOURCE_DIR}/include)
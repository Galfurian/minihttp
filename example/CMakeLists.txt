add_executable(${PROJECT_NAME}_example example.cpp)
target_link_libraries(${PROJECT_NAME}_example PRIVATE minihttp)
target_include_directories(${PROJECT_NAME}_example PRIVATE ${PROJECT_SOURCE_DIR}/include)

add_executable(${PROJECT_NAME}_get_example get_example.cpp)
target_link_libraries(${PROJECT_NAME}_get_example PRIVATE minihttp)
target_include_directories(${PROJECT_NAME}_get_example PRIVATE ${PROJECT_SOURCE_DIR}/include)

add_executable(${PROJECT_NAME}_post_example post_example.cpp)
target_link_libraries(${PROJECT_NAME}_post_example PRIVATE minihttp)
target_include_directories(${PROJECT_NAME}_post_example PRIVATE ${PROJECT_SOURCE_DIR}/include)

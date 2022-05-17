add_executable(${PROJECT_NAME}_example example.cpp)
target_link_libraries(${PROJECT_NAME}_example PRIVATE minihttp)
target_include_directories(${PROJECT_NAME}_example PRIVATE ${PROJECT_SOURCE_DIR}/include)

add_executable(example main.cpp)
target_link_libraries(example PRIVATE minihttp)
target_include_directories(example PRIVATE ${PROJECT_SOURCE_DIR}/include)

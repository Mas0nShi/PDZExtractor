cmake_minimum_required(VERSION 3.28)
project(PDZExtractor)

set(CMAKE_CXX_STANDARD 17)

aux_source_directory(cipher CIPHER_SRC)
add_executable(${CMAKE_PROJECT_NAME} PDZExtractor.cpp ${CIPHER_SRC})

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(third_party/tinyxml2)
add_subdirectory(third_party/tinyxml2)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE tinyxml2)

include_directories(third_party/CLI11/include)
add_subdirectory(third_party/CLI11)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE CLI11)

# macos need remove -static
if (NOT APPLE)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE -static)
endif ()

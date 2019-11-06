cmake_minimum_required(VERSION 3.10)

project(TestBoostASIO LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Boost 1.65 COMPONENTS system)
if (NOT Boost_FOUND)
    message(FATAL_ERROR "sudo apt-get --no-install-recommends install libboost-system-dev")
endif()

add_executable(main main.cpp)
target_include_directories(main PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(main PRIVATE ${Boost_LIBRARIES})

cmake_minimum_required(VERSION 3.13.4)
project(MyDemoProject LANGUAGES C)

add_executable(main "main.c")
set_property(TARGET main PROPERTY C_STANDARD 11)

find_package(PkgConfig 0.27.1 REQUIRED)
if (!PkgConfig_FOUND)
    message(FATAL_ERROR "You must install pkg-config!")
endif ()
pkg_check_modules(CONCURRENCY_KIT "ck>=0.5.2" REQUIRED)
find_library(CONCURRENCY_KIT_LIBRARIES
    NAMES ck
    HINTS ${CONCURRENCY_KIT_LIBDIR} ${CONCURRENCY_KIT_LIBRARY_DIRS}
)
target_include_directories(main PRIVATE ${CONCURRENCY_KIT_INCLUDE_DIRS})
target_link_libraries(main ${CONCURRENCY_KIT_LIBRARIES})

cmake_minimum_required(VERSION 3.13.4)
project(MyDemoProject LANGUAGES C)

add_executable(main "main.c")
set_property(TARGET main PROPERTY C_STANDARD 11)

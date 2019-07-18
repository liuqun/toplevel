cmake_minimum_required(VERSION 3.13.4)
project(MyDemoProject LANGUAGES C)

aux_source_directory(src server_SOURCES)
add_executable(server ${server_SOURCES})
set_property(TARGET server PROPERTY C_STANDARD 11)

find_package(OpenSSL REQUIRED)
if (!OpenSSL_FOUND)
  message(WARNING "Try: sudo apt install libssl-dev")
  message(FATAL_ERROR "OpenSSL are required but not found!")
endif ()
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
message(STATUS "Using include dir ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Using libssl ${OPENSSL_SSL_LIBRARY}")
message(STATUS "Using libcrypto ${OPENSSL_CRYPTO_LIBRARY}")
target_include_directories(server PRIVATE
  ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(server PRIVATE
  ${OPENSSL_LIBRARIES}
)

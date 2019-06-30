// Demo code from ASIO C++ library tutorials
// -----------------------------------------
// Modified from:
// https://think-async.com/Asio/asio-1.13.0/doc/asio/tutorial/tutdaytime5/src.html
//
// How to compile:
//     g++ -g -O0 -pthread -std=c++11 -c udp_daytime_server.cpp -lpthread
// Run:
//     ./a.out

#include <ctime>
#include <cstdio>
#include <string>
#include <boost/array.hpp>
#include <asio.hpp>

using asio::ip::udp;

#include <asio/version.hpp>
#if defined(ASIO_VERSION) && ASIO_VERSION <= 101008
namespace asio {
    class io_context : public asio::io_service {};
};
#endif

std::string make_daytime_string()
{
    using namespace std;
    // For time_t, time and ctime;
    time_t now = time(0);
    return ctime(&now);
}

int main()
{
    const int DEFAULT_PORT = 8013; // port 13 requires root access, use 8013 instead...

    try {
        asio::io_context io_context;

        udp::socket socket(io_context, udp::endpoint(udp::v4(), DEFAULT_PORT));

        for (;;) {
            boost::array<char, 1> recv_buf;
            udp::endpoint remote_endpoint;
            asio::error_code error;
            socket.receive_from(asio::buffer(recv_buf), remote_endpoint);

            std::string message = make_daytime_string();

            asio::error_code ignored_error;
            socket.send_to(asio::buffer(message), remote_endpoint, 0, ignored_error);
        }
    } catch (std::system_error& e) {
        std::fprintf(stderr, "%s\n", e.what());
    }

    return 0;
}

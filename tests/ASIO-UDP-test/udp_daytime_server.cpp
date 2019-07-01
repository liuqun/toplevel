// Demo code from ASIO C++ library tutorials
// -----------------------------------------
// Modified from:
// https://think-async.com/Asio/asio-1.13.0/doc/asio/tutorial/tutdaytime5/src.html
//
// How to compile:
//     sudo apt install g++-9
//     g++-9 -g -O0 -pthread -std=c++2a -c udp_daytime_server.cpp -lpthread
// Run:
//     ./a.out

#include <ctime>
#include <cstdio>
#include <string>
#include <array>
using std::array;
#include <system_error>
using std::error_code;
#include <experimental/net>
//#include <experimental/socket>
using namespace std::experimental::net::v1;
//using std::experimentall::net::error_code;

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
    const int DEFAULT_PORT = 13; // port 13 requires root access, use 8013 instead...

    try {
        io_context io_context;

	ip::udp::socket socket(io_context, ip::udp::endpoint(ip::udp::v4(), DEFAULT_PORT));
	fprintf(stderr, "aaa\n");

        for (;;) {
            array<char, 1> recv_buf;
	    ip::udp::endpoint remote_endpoint;
	    error_code error;
	fprintf(stderr, "bbb\n");
            socket.receive_from(_BufferSequence(recv_buf), remote_endpoint);
	fprintf(stderr, "cc\n");

            std::string message = make_daytime_string();

            error_code ignored_error;
            socket.send_to(_ConstBufferSequence(message), remote_endpoint, 0, ignored_error);
	fprintf(stderr, "ddd\n");
        }
    } catch (std::system_error& e) {
        std::fprintf(stderr, "%s\n", e.what());
    }

    return 0;
}

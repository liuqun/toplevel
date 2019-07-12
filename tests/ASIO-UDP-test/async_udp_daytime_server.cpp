// 基于ASIO的异步UDP Demo Daytime服务器
// ------------------------------------
// 代码源自ASIO入门教程，有改动：
//  - https://think-async.com/Asio/asio-1.13.0/doc/asio/tutorial/tutdaytime6/src.html
//
// 编译：
//     g++ -g -O0 -pthread -std=c++11 async_udp_daytime_server.cpp -lpthread
//
// 运行测试：
//     ./a.out
//
// 教程代码仅供学习参考，未经测试请勿用于生产环境！
//

#include <ctime>
#include <cstdio>
#include <array> // using std::array;
#include <memory> // using std::shared_ptr;
#include <string>
#include <boost/bind.hpp>
#include <asio.hpp>

using asio::ip::udp;
using std::fprintf;

#include <asio/version.hpp>
#if defined(ASIO_VERSION) && ASIO_VERSION <= 101008
namespace asio {
    typedef asio::io_service io_context;
}
#endif

std::string make_daytime_string()
{
    using namespace std;
    // For time_t, time and ctime;
    time_t now = time(0);
    return ctime(&now);
}

class udp_server {
public:
    udp_server(udp::socket& sock) : sock_(sock)
    {
        async_wait_for_next_incoming_packet();
    }

private:
    void async_wait_for_next_incoming_packet()
    {
        sock_.async_receive_from(asio::buffer(recv_buffer_), remote_endpoint_,
                boost::bind(&udp_server::parse_incoming_packet_and_async_send_reply, this,
                        asio::placeholders::error,
                        asio::placeholders::bytes_transferred));
    }

    void parse_incoming_packet_and_async_send_reply(const asio::error_code& error,
            std::size_t bytes_transferred)
    {
        if (error) {
            return;
        }
        fprintf(stdout, "Debug: %d bytes received:\n", (int)bytes_transferred);
        fprintf(stdout, "Debug: recv_buffer_[0]='%c'\n", recv_buffer_[0]);


        std::shared_ptr<std::string> p(new std::string(make_daytime_string()));

        sock_.async_send_to(asio::buffer(*p), remote_endpoint_,
                boost::bind(&udp_server::after_async_send_to, this, p,
                        asio::placeholders::error,
                        asio::placeholders::bytes_transferred));

        async_wait_for_next_incoming_packet();
    }

    void after_async_send_to(
            std::shared_ptr<std::string> p,
            const asio::error_code& error,
            std::size_t bytes_transferred)
    {
    }

    udp::socket& sock_;
    udp::endpoint remote_endpoint_;
    static const unsigned RECV_BUFFER_SIZE = 1500;
    std::array<char, RECV_BUFFER_SIZE> recv_buffer_;
};


const int DEFAULT_DAYTIME_SERVICE_PORT = 13;

#define UDP_ONLY_IPV4 (udp::v4())
#define UDP_BOTH_IPV4V6 (udp::v6())


int main(void)
{
    int port;
    int retry;
    asio::io_context io_context;
    udp::socket sock(io_context, UDP_BOTH_IPV4V6);

    port = DEFAULT_DAYTIME_SERVICE_PORT;
    for (retry=2; retry>0; retry-=1) {
        fprintf(stdout, "Preparing to run daytime server on UDP service port %d... \n", port);
        try {
            sock.bind(udp::endpoint(UDP_BOTH_IPV4V6, port));
        } catch (std::system_error& e) {
            fprintf(stderr, "Warning: Failed to start server on UDP port %d: %s\n", port, e.what());
            port += 8000;
            continue;
        }
        fprintf(stdout, "Listening on UDP service port %d...\n", port);
        udp_server server(sock);
        io_context.run();
        /* Normal exit: */
        return 0;
    }
    /* Error exit: */
    if (retry<=0) {
        fprintf(stderr, "ERROR: Unable to create UDP server! Stop retrying...\n");
    }
    return 255;
}

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

const std::string make_daytime_string()
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
        async_receive_next_incoming_packet(incoming_packet_.data(), incoming_packet_.size(), remote_endpoint_);
    }

private:
    void async_receive_next_incoming_packet(void *buf, size_t buf_size, udp::endpoint& remote_peer_ip_port)
    {
        sock_.async_receive_from(asio::buffer(buf, buf_size), remote_peer_ip_port,
                boost::bind(&udp_server::on_packet_received, this,
                        (const char*)buf,
                        asio::placeholders::bytes_transferred,
                        remote_peer_ip_port,
                        asio::placeholders::error));
    }

    void on_packet_received(
            const char              *data,
            std::size_t             bytes_transferred,
            const udp::endpoint&    remote_peer_ip_port,
            const asio::error_code& error)
    {
        if (error) {
            return;
        }
        fprintf(stdout, "Debug: %d bytes received:\n", (int)bytes_transferred);
        fprintf(stdout, "Debug: data[0]=0x%02X\n", data[0]);

        const std::string& reply = make_daytime_string();
        async_send_next_outgoing_packet(reply.c_str(), reply.length(), remote_peer_ip_port);

        async_receive_next_incoming_packet(incoming_packet_.data(), incoming_packet_.size(), remote_endpoint_);
    }

    void async_send_next_outgoing_packet(const void *data, size_t dlen, const udp::endpoint& remote_peer_ip_port)
    {
        sock_.async_send_to(asio::buffer(data, dlen), remote_peer_ip_port,
                boost::bind(&udp_server::on_transmission_finished, this,
                        asio::placeholders::bytes_transferred,
                        asio::placeholders::error));
    }

    void on_transmission_finished(std::size_t bytes_transferred, const asio::error_code& error)
    {
    }

    udp::socket& sock_;
    udp::endpoint remote_endpoint_;
    static const unsigned MAX_INCOMING_PACKET_LENGTH = 8*1024; // UDP报文长度理论最大值 0xFFFF = 65535 Bytes < 64KiB
    std::array<char, MAX_INCOMING_PACKET_LENGTH> incoming_packet_;
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

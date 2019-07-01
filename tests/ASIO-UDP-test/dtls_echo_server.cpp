// 仅供内部交流使用, 未经严格测试前不得用于生产环境!
// Copyright: 2019, 青岛新范式信息技术有限公司

#include <cstdio>
#include <string>
#include <boost/array.hpp>
#include <asio.hpp>

using asio::ip::udp;
using std::fprintf;

#include <asio/version.hpp>
#if defined(ASIO_VERSION) && ASIO_VERSION <= 101008
namespace asio {
    class io_context : public asio::io_service {};
}
#endif

#define IPV4_ONLY (udp::v4())
#define IPV6_ONLY (udp::v6())
const int DEFAULT_PORT = 8007; // default Unix echo service port 7 requires root access, use 8007 instead...

#include <unordered_map>
//using std::unordered_map;

#include <openssl/ssl.h>

extern "C"{

typedef struct _peer_info_t {
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;
}peer_info_t;

};

int main()
{
    asio::io_context io_context;
    udp::socket socket(io_context, IPV4_ONLY);
    udp::endpoint server_ip_and_port(IPV4_ONLY, DEFAULT_PORT);
    udp::endpoint client_ip_and_port;
    asio::error_code err_code_bind;
    asio::error_code err_code_send;
    boost::array<char, 1500> plaintext;
    std::unordered_map<int, peer_info_t> peer_tbl;

    socket.bind(server_ip_and_port, err_code_bind);
    if (err_code_bind) {
        const char *ip = server_ip_and_port.address().to_string().c_str();
        const int port = server_ip_and_port.port();
        fprintf(stderr, "ERROR: Unable to bind local UDP port at %s:%d! %s\n",
                ip, port, err_code_bind.message().c_str());
        return 0;
    }
    for (;;) {
        int n = socket.receive_from(asio::buffer(plaintext), client_ip_and_port);
        fprintf(stdout, "DEBUG: server received %d bytes, plaintext[0] = 0x%02X\n", n, plaintext[0]);
        std::unordered_map<int, peer_info_t>::iterator peer;
        const int port = client_ip_and_port.port();
        peer = peer_tbl.find(port);
        if (peer_tbl.end() == peer) {
            peer_info_t info;
            info.ssl = NULL;
            info.rbio = info.wbio = NULL;
            peer_tbl[port] = info;
        }
        fprintf(stdout, "DEBUG: peer_tbl.size() = %d\n", (int)peer_tbl.size());
        std::string reply(plaintext.data(), n);
        socket.send_to(asio::buffer(reply), client_ip_and_port, 0, err_code_send);
    }
    return 0;
}

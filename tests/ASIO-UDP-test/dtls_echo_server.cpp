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




class PeerRecord {
public:



public:
    PeerRecord(const udp::endpoint& peer_ip_and_port): m_peer_ip_and_port(peer_ip_and_port)
    {
        m_ssl = nullptr;
        m_incoming = m_outgoing = nullptr;
    }
    //explicit PeerRecord(string name, string phone, string address): name(name), phone(phone), address(address) {}

    // // 重写自定义的"等于等于"运算符 @Override operator==
    // bool operator==(const PeerRecord& other)
    // {
    //     return this->m_peer_ip_and_port == other.m_peer_ip_and_port;
    // }


public:
    SSL *m_ssl;
    BIO *m_incoming; // incoming DTLS ciphertext data will be cached in this BIO
    BIO *m_outgoing; // outgoing DTLS ciphertext data will be cached in this BIO
    //std::string debug;
    udp::endpoint m_peer_ip_and_port;
};

// bool operator==(const PeerRecord& lhs, const PeerRecord& rhs) {
//     return lhs.m_peer_ip_and_port == rhs.m_peer_ip_and_port;
// }


// 自定义的 C++ 哈希计算模板 hash<udp::endpoint>
// 并且将此模板注入进 namespace std 默认命名空间
namespace std
{
    template <> struct hash<udp::endpoint>
    {
        std::size_t operator()(const udp::endpoint& peer_ip_and_port) const
        {
            const std::string& ip_address_str = peer_ip_and_port.address().to_string();
            int port = peer_ip_and_port.port();

            std::hash<std::string> digest_from_string;
            std::hash<int> digest_from_int;
            return digest_from_string(ip_address_str) ^ digest_from_int(port);
        }
    };
}

/*
struct MyHashAlgorithm{
    std::size_t operator()(const udp::endpoint& peer_ip_and_port) const
    {
        const std::string& ip_address_str = peer_ip_and_port.address().to_string();
        int port = peer_ip_and_port.port();

        std::hash<std::string> digest_from_string;
        std::hash<int> digest_from_int;
        return digest_from_string(ip_address_str) ^ digest_from_int(port);
    }
};
*/

int main()
{
    asio::io_context io_context;
    udp::socket socket(io_context, IPV4_ONLY);
    udp::endpoint server_ip_and_port(IPV4_ONLY, DEFAULT_PORT);
    udp::endpoint client_ip_and_port;
    asio::error_code err_code_bind;
    asio::error_code err_code_send;
    boost::array<char, 1500> recvbuf;
    std::unordered_map<udp::endpoint, PeerRecord> connected_peers;

    socket.bind(server_ip_and_port, err_code_bind);
    if (err_code_bind) {
        const char *ip = server_ip_and_port.address().to_string().c_str();
        const int port = server_ip_and_port.port();
        fprintf(stderr, "ERROR: Unable to bind local UDP port at %s:%d! %s\n",
                ip, port, err_code_bind.message().c_str());
        return 0;
    }
    for (;;) {
        int n = socket.receive_from(asio::buffer(recvbuf), client_ip_and_port);
        fprintf(stdout, "DEBUG: server received %d bytes, recvbuf[0] = 0x%02X\n", n, recvbuf[0]);
        PeerRecord *ptr=nullptr;
        auto got = connected_peers.find(client_ip_and_port); // std::unordered_map<udp::endpoint,PeerRecord>::const_iterator
        if (connected_peers.end() == got) /* 若查不到来自此客户端的访问记录 */ {
            ptr = new PeerRecord(client_ip_and_port);
            PeerRecord& record = *ptr;
            record.m_ssl = nullptr;
            record.m_incoming = nullptr;
            record.m_outgoing = nullptr;
            auto ret = connected_peers.insert(std::pair<udp::endpoint, PeerRecord> {client_ip_and_port, record});
        }
        else
        {
            ptr = &(got->second);
        }
        //BIO_write(record.incoming

        fprintf(stdout, "DEBUG: connected_peers.size() = %d\n", (int)connected_peers.size());
        std::string reply("a", 1);
        socket.send_to(asio::buffer(reply), client_ip_and_port, 0, err_code_send);
    }
    return 0;
}

// 仅供内部交流使用, 未经严格测试前不得用于生产环境!
// Copyright: 2019, 青岛新范式信息技术有限公司

/*
How to compile in Ubuntu 18.04:
    g++ -g -O0 -pthread -I./inc/asio-1.10.8 -I./inc/boost-1.65.1 udp_echo_server.cpp
    ./a.out
*/

#include <cstdio>
#include <string>
#include <boost/array.hpp>
#include <asio.hpp>

using asio::ip::udp;
using std::fprintf;

#include <asio/version.hpp>
#if defined(ASIO_VERSION) && ASIO_VERSION <= 101008
namespace asio {
    typedef asio::io_service io_context;
}
#endif

#define IPV4_ONLY (udp::v4())
#define IPV4_V6_BOTH (udp::v6())
const int DEFAULT_PORT = 8007; // default Unix echo service port 7 requires root access, use 8007 instead...

static std::string get_ipv4_addresses_from_all_network_adapters();
static std::string get_ipv4v6_addresses_from_all_network_adapters();

int main()
{
    using std::string;

    asio::io_context io_context;
    udp::socket socket(io_context, IPV4_ONLY);
    udp::endpoint server_ip_and_port(IPV4_ONLY, DEFAULT_PORT);
    udp::endpoint client_ip_and_port;
    asio::error_code err_code_bind;
    asio::error_code err_code_send;
    boost::array<char, 1500> plaintext;

    const string ipv4_list   = get_ipv4_addresses_from_all_network_adapters();
    const string ipv4v6_list = get_ipv4v6_addresses_from_all_network_adapters();
    if (server_ip_and_port.address().is_v4()) {
        printf("Info: IPv4 addresses: %s\n", ipv4_list.c_str());
    } else {
        printf("Info: IP(v4/v6) addresses: %s\n", ipv4v6_list.c_str());
    }

    int  listener_port = server_ip_and_port.port();
    string listener_ip = server_ip_and_port.address().to_string();
    if (server_ip_and_port.address().is_v6()) {
        listener_ip = "[" + listener_ip + "]";
    }

    printf("Info: Try to bind local UDP port %d...\n", listener_port);
    socket.bind(server_ip_and_port, err_code_bind);
    if (err_code_bind) {
        fprintf(stderr, "ERROR: Unable to bind local UDP port at %s:%d! %s\n",
                listener_ip.c_str(), listener_port, err_code_bind.message().c_str());
        return 0;
    }
    printf("Info: Listening at UDP port %d...\n", listener_port);
    for (;;) {
        size_t n = socket.receive_from(asio::buffer(plaintext), client_ip_and_port);
        if (0 == n) {
            break;
        }
        int  client_port = client_ip_and_port.port();
        string client_ip = client_ip_and_port.address().to_string();
        fprintf(stdout, "Server received %d bytes, plaintext[0] = '%c'\n", static_cast<int>(n), plaintext[0]);
        fprintf(stdout, "  from client ip:port=%s:%d\n", client_ip.c_str(), client_port);

        std::string reply(plaintext.data(), n);
        socket.send_to(asio::buffer(reply), client_ip_and_port, 0, err_code_send);
    }
    return 0;
}


#include <netinet/in.h>
#include <sys/types.h>
#include <ifaddrs.h>

std::string get_ipv4v6_addresses_from_all_network_adapters()
{
    int cnt = 0;
    struct ifaddrs *ifa_list;
    struct ifaddrs *ifa;

    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    char strbuf4[INET_ADDRSTRLEN] = "";
    char strbuf6[INET6_ADDRSTRLEN] = "";

    std::string ip_list("");
    ifa_list = nullptr;
    getifaddrs(&ifa_list);
    if (!ifa_list) {
        return "";
    }
    for (ifa=ifa_list; ifa; ifa=ifa->ifa_next) {
        // IPv4
        if (AF_INET == ifa->ifa_addr->sa_family) {
            sin = reinterpret_cast<sockaddr_in *>(ifa->ifa_addr);
            void *sin_addr = &(sin->sin_addr);
            if (!inet_ntop(AF_INET, sin_addr, strbuf4, sizeof(strbuf4))) {
                continue;
            }
            if (cnt >= 1) {
                ip_list.append(" || ");
            }
            ip_list.append(strbuf4);
            cnt += 1;
            continue;
        }

        if (AF_INET6 != ifa->ifa_addr->sa_family) {
            continue; // neither IPv4 nor IPv6
        }

        // IPv6
        sin6 = reinterpret_cast<sockaddr_in6 *>(ifa->ifa_addr);
        void *sin6_addr = &(sin6->sin6_addr);
        if (!inet_ntop(AF_INET6, sin6_addr, strbuf6, sizeof(strbuf6))) {
            continue;
        }
        if (cnt >= 1) {
            ip_list.append(" || ");
        }
        ip_list.append(strbuf6);
        cnt += 1;
    }
    freeifaddrs(ifa_list);
    return ip_list;
}

std::string get_ipv4_addresses_from_all_network_adapters()
{
    int cnt = 0;
    struct ifaddrs *ifa_list;
    struct ifaddrs *ifa;

    struct sockaddr_in *sin;
    char strbuf[INET_ADDRSTRLEN] = "";

    std::string ip_list("");
    ifa_list = nullptr;
    getifaddrs(&ifa_list);
    if (!ifa_list) {
        return "";
    }
    for (ifa=ifa_list; ifa; ifa=ifa->ifa_next) {
        if (AF_INET != ifa->ifa_addr->sa_family) {
            continue; // skip IPv6
        }
        // IPv4
        sin = reinterpret_cast<sockaddr_in *>(ifa->ifa_addr);
        void *sin_addr = &(sin->sin_addr);
        if (!inet_ntop(AF_INET, sin_addr, strbuf, sizeof(strbuf))) {
            continue;
        }
        if (cnt >= 1) {
            ip_list.append(" || ");
        }
        ip_list.append(strbuf);
        cnt += 1;
    }
    freeifaddrs(ifa_list);
    return ip_list;
}

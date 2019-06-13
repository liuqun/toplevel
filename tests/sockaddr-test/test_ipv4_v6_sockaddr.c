#include <netinet/in.h>
// struct sockaddr_in; // IPv4专用: sockaddr_in结构体, 含有: 2字节协议簇号 + 2字节端口号 + 4字节IPv4地址 + 尾部空白8字节
// struct sockaddr_in6;// IPv6专用: sockaddr_in6结构体, 含有: 2字节协议簇号 + 2字节端口号 + 4字节空白 + 16字节IPv6地址 + 尾部空白4字节
//
// 为了统一各种协议，socket对应的接口就定义了两个通用结构，分别是:
//   1. sockaddr(16字节)
//   2. sockaddr_storage(128字节)
// 注意sockaddr_storage是为了适配sockaddr_in6(28字节)这样长度比较大的协议而后来定义的.
//
// sockaddr    结构体总长 sizeof(struct sockaddr)=16 字节
// sockaddr_in 结构体总长 sizeof(struct sockaddr_in)=16 字节
// sockaddr_in6 结构体总长 sizeof(struct sockaddr_in6)=28 字节
// sockaddr_storage 结构体总长 sizeof(struct sockaddr_storage)=128 字节

#include <stdio.h>
#include <string.h>

int main()
{

    printf("sockaddr    结构体总长 sizeof(struct sockaddr)=%d 字节\n", (int)sizeof(struct sockaddr));
    printf("sockaddr_in 结构体总长 sizeof(struct sockaddr_in)=%d 字节\n", (int)sizeof(struct sockaddr_in));
    printf("sockaddr_in6 结构体总长 sizeof(struct sockaddr_in6)=%d 字节\n", (int)sizeof(struct sockaddr_in6));


    struct sockaddr_in6 ipv6;
    struct sockaddr_in ipv4;

    short port = 80;

    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(port);
    memset(&ipv4.sin_addr, 0x00, sizeof(ipv4.sin_addr)); // IP地址全0表示0.0.0.0, 用于服务器bind任意本地IP地址

    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(port);
    memset(&ipv6.sin6_addr, 0x00, sizeof(ipv6.sin6_addr));

    printf("一、IPv4: struct sockaddr_in 结构体包含:\n");
    printf("  v4地址簇代码%d字节 + 端口号%d字节 + IPv4地址长度%d字节 + 尾部填充空白%d字节\n", (int)sizeof(ipv4.sin_family), (int)sizeof(ipv4.sin_port), (int)sizeof(ipv4.sin_addr), (int)sizeof(ipv4.sin_zero));
    printf("  sizeof(struct sockaddr_in) 共 %d 字节\n", (int)sizeof(struct sockaddr_in));
    printf("\n");

    printf("二、IPv6: struct sockaddr_in6 结构体包含:\n");
    printf("  v6地址簇代码%d字节 + 端口号%d字节 + 留空%d字节 + IPv6地址长度%d字节 + 尾部留空%d字节\n", (int)sizeof(ipv6.sin6_family), (int)sizeof(ipv6.sin6_port), (int)sizeof(ipv6.sin6_flowinfo), (int)sizeof(ipv6.sin6_addr), (int)sizeof(ipv6.sin6_scope_id));
    printf("注意 sizeof(struct sockaddr_in6) 共 %d 字节\n", (int)sizeof(struct sockaddr_in6));
    printf("\n");

    struct sockaddr_storage storage;
    printf("三、sockaddr_storage 结构体总长 sizeof(struct sockaddr_storage)=%d 字节\n", (int)sizeof(struct sockaddr_storage));
    printf("  sizeof(__ss_padding)=%d 字节\n", (int)sizeof(storage.__ss_padding));
    printf("  sizeof(__ss_align)=%d 字节\n", (int)sizeof(storage.__ss_align));


    // 自定义联合体长度 sizeof(xfs_sockaddr_t)=128 字节
    typedef union {
        struct sockaddr         addr;
        struct sockaddr_in      addr_v4;
        struct sockaddr_in6     addr_v6;
        struct sockaddr_storage addr_storage;
    } xfs_sockaddr_t;
    printf("四、自定义联合体长度 sizeof(xfs_sockaddr_t)=%d 字节\n", (int)sizeof(xfs_sockaddr_t));
}


#if 0
// 详细说明
#include <netinet/in.h>

typedef unsigned short int  sa_family_t;
typedef uint16_t            in_port_t;
typedef uint32_t            in_addr_t;

struct sockaddr_in {
    sa_family_t sin_family;              /* Address family: 2字节地址簇 AF_INET */
    in_port_t sin_port;                  /* TCP/UDP 端口号(2字节) */
    struct {
        in_addr_t s_addr;                /* IPv4 地址(4字节) */
    } sin_addr;
    unsigned char sin_zero[8];           /* 为了与 struct sockaddr 结构体等长而补加的8字节 */
};


struct sockaddr_in6 {
    sa_family_t sin6_family;             /* Address family: 2字节地址簇 AF_INET6 */
    in_port_t sin6_port;                 /* TCP/UDP 端口号 */
    uint32_t sin6_flowinfo;              /* IPv6 traffic class & flow info */
    struct {
        uint8_t s6_addr[16];             /* IPv6 地址 16 字节 */
    } sin6_addr;
    uint32_t sin6_scope_id;              /* set of interfaces for a scope */
};


struct sockaddr {
    sa_family_t sa_family;               /* 2字节地址簇 AF_XXX */
    char sa_data[14];                    /* 14字节 */
};


struct sockaddr_storage {
    sa_family_t sin_family;              /* Address family: 2字节地址簇 AF_INET */
    char __ss_padding[_SS_PADSIZE];
    __ss_aligntype __ss_align; /* Force desired alignment.  */
};



#include <sys/types.h>
#include <sys/socket.h>

// UDP 发包/收包函数
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

// TCP/UDP服务器通用bind()函数:
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// TCP 函数: conncet/accept/发包/收包/listen
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int listen(int sockfd, int backlog);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);

// 特殊sockopt选项的设定和查询
int setsockopt(int sockfd, int level, int optname,
                const void *optval, socklen_t optlen);
int getsockopt(int sockfd, int level, int optname,
                void *optval, socklen_t *optlen);

// 字符串 ==> IPv4/6地址
// convert from text to binary IPv4 and IPv6 addresses
int inet_pton(int af, const char *src, void *dst);

// IPv4/6地址 ==> 字符串
// convert IPv4 and IPv6 addresses from binary to text
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#endif

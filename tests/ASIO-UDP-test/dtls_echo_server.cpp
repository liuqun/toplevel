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




/* 客户端访问会话记录 */
class PeerRecord {
public:
    PeerRecord()//PeerRecord(const udp::endpoint& peer_ip_and_port): m_peer_ip_and_port(peer_ip_and_port)
    {
        m_ssl = nullptr;
        m_incoming_bio = m_outgoing_bio = nullptr;
    }

public:
    SSL *m_ssl;
    BIO *m_incoming_bio; // incoming DTLS ciphertext data will be cached in this BIO
    BIO *m_outgoing_bio; // outgoing DTLS ciphertext data will be cached in this BIO
    //注: udp::endpoint m_peer_ip_and_port;
};

/* 【哈希函数的两种写法如下】 */
/* 自定义哈希函数1: */
struct MyHashAlgorithm {
    size_t operator()(const udp::endpoint& peer_ip_and_port) const
    {
        const std::string& ip_address_str = peer_ip_and_port.address().to_string();
        int port = peer_ip_and_port.port();
        std::hash<std::string> get_hash_digest_from_string;

        return get_hash_digest_from_string(ip_address_str + ":" + std::to_string(port));// 对 "IP地址:端口" 字符串进行哈希
    }
};/* end 自定义哈希函数1 */

/* 自定义哈希函数写法2 (与写法1最终效果相同, 只是写法2的书写格式更繁琐一些. 此处暂不启用该写法) */
#if 1
    // 定义一个以地址+端口号为被处理对象的哈希函数模板 hash<udp::endpoint>
    // 同时, 将此模板注入进 namespace std 默认命名空间, 使C++编译器能够自动调用相应的哈希函数
    namespace std
    {
        template <> struct hash<udp::endpoint>
        {
            std::size_t operator()(const udp::endpoint& peer_ip_and_port) const
            {
                const std::string& ip_address_str = peer_ip_and_port.address().to_string();
                int port = peer_ip_and_port.port();
                hash<std::string> get_hash_digest_from_string;

                return get_hash_digest_from_string(ip_address_str + ":" + std::to_string(port));
            }
        };
    }
#endif /* end 自定义哈希函数2 */



extern "C" {
    typedef struct _ServerAppConf {
        SSL_CTX *ctx;
    }ServerAppConf;

    /* 子函数声明 */
    static void server_app_apply_default_configuation(ServerAppConf *conf);
    static int server_app_generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
    static int server_app_verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);
    static char char_from_int(int byte);
}; // end of extern "C"


int main()
{
    asio::io_context io_context;
    udp::socket socket(io_context, IPV4_ONLY);
    udp::endpoint server_ip_and_port(IPV4_ONLY, DEFAULT_PORT);
    udp::endpoint client_ip_and_port;
    asio::error_code err_code_bind;
    asio::error_code err_code_send;
    boost::array<char, 3000> recvbuf;
    /* 使用 C++ 标准模版库的 std::unordered_map<> 哈希表模版,
       将所有客户端的信息按 IP 地址和 UDP 端口号排列起来 */
    std::unordered_map<udp::endpoint, PeerRecord, MyHashAlgorithm> connected_peers;

    socket.bind(server_ip_and_port, err_code_bind);
    if (err_code_bind) {
        const char *ip = server_ip_and_port.address().to_string().c_str();
        const int port = server_ip_and_port.port();
        fprintf(stderr, "ERROR: Unable to bind local UDP port at %s:%d! %s\n",
                ip, port, err_code_bind.message().c_str());
        return 0;
    }

    ServerAppConf server_app_conf;
    server_app_apply_default_configuation(&server_app_conf);
    if (!server_app_conf.ctx) {
        fprintf(stderr, "ERROR: Failed to load server application configuation!\n"
                        "       Please check server keys and certs!\n");
        return 0;
    }

    PeerRecord record;
    record.m_ssl = nullptr;
    record.m_incoming_bio = nullptr;
    record.m_outgoing_bio = nullptr;
    for (;;) {
        fprintf(stderr, "DEBUG: Now we have %d DTLS clients to talk with.\n", (int)connected_peers.size());

        const void *incoming_data = recvbuf.data();
        int n = socket.receive_from(asio::buffer(recvbuf), client_ip_and_port);
        fprintf(stdout, "DEBUG: server received %d bytes, recvbuf[0] = 0x%02X\n", n, recvbuf[0]);
        if (n > 1456) {
            fprintf(stdout, "Warning: n=%d, 数据段长度n>1456 对应的IP包总长可能>1500(此包可能源自若干IP分片组合而成)\n", n);
        }

        PeerRecord *p;
        p = &record;
        auto search_result = connected_peers.find(client_ip_and_port);
        if (search_result != connected_peers.end()){
            /* 根据已有的访问记录, 记录与此客户端进行UDP通讯 */
            p = &(search_result->second);
        } else {
            /* 新建 SSL 以及输入输出 BIO 缓存 */
            SSL *ssl;
            BIO *incoming_bio;
            BIO *outgoing_bio;
            SSL_CTX *ctx;

            ctx = server_app_conf.ctx;
            ssl = SSL_new(ctx);
            incoming_bio = BIO_new(BIO_s_mem());
            outgoing_bio = BIO_new(BIO_s_mem());
            BIO_set_mem_eof_return(incoming_bio, -1);
            BIO_set_mem_eof_return(outgoing_bio, -1);
            SSL_set0_rbio(ssl, incoming_bio);
            SSL_set0_wbio(ssl, outgoing_bio);
            SSL_set_accept_state(ssl);
            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
            SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

            record.m_ssl = ssl;
            record.m_incoming_bio = incoming_bio;
            record.m_outgoing_bio = outgoing_bio;

            /* 以客户端IP地址端口号为key, 插入一条新的 PeerRecord 访问记录到connected_peers, 记录来自此 UDP 端口的客户端 */
            auto pair = connected_peers.insert(std::pair<udp::endpoint, PeerRecord> {client_ip_and_port, record});
            auto item = pair.first;
            p = &(item->second); // 让指向哈希表内部存储的 record 结构体一个副本
            // 然后清空 record 结构体原始空间
            record.m_ssl = nullptr;
            record.m_incoming_bio = nullptr;
            record.m_outgoing_bio = nullptr;
        }

        BIO_write(p->m_incoming_bio, incoming_data, n);
        fprintf(stderr, "DEBUG: LINE=%d,  incoming_data %d byte written into bio\n", __LINE__, n);

        if ( SSL_get_state(p->m_ssl) != TLS_ST_OK ) {
            /* 若此时客户端尚未完成 DTLS 握手, 则先收发握手包: */
            int check = SSL_do_handshake(p->m_ssl);
fprintf(stderr, "DEBUG: LINE=%d,  check = %d\n", __LINE__, check);
            if (1 != check) {

            }
            if ( 1 == check ) {
                fprintf(stderr, "DEBUG: LINE=%d, handshake finished.\n", __LINE__);
            }

                char handshake_packet_cache[3000];
                const int max_cache_bytes = sizeof(handshake_packet_cache);
                int outgoing_len;

                outgoing_len = BIO_ctrl_pending(p->m_outgoing_bio);
fprintf(stderr, "DEBUG: LINE=%d,  outgoing_len = %d\n", __LINE__, outgoing_len);
                if (outgoing_len <= 0) {
                    continue;
                }
                if (outgoing_len > max_cache_bytes) {
                    outgoing_len = max_cache_bytes;
                }
                BIO_read(p->m_outgoing_bio, handshake_packet_cache, outgoing_len);
                socket.send_to(asio::buffer(handshake_packet_cache, outgoing_len), client_ip_and_port, 0, err_code_send);

                continue;
        }

        char plaintext[1500];
        const int max_plaintext_bytes = sizeof(plaintext);
        int plaintext_len = SSL_read(p->m_ssl, plaintext, max_plaintext_bytes);
        fprintf(stderr, "DEBUG: LINE:%d: plaintext_len %d bytes.\n", __LINE__, plaintext_len);

        if (plaintext_len <= 0) {
            SSL *ssl = p->m_ssl;
            int stateflag = SSL_get_shutdown(ssl);
            if (stateflag & SSL_RECEIVED_SHUTDOWN)
            {
                int shutdown_status;
                const char *ip = client_ip_and_port.address().to_string().c_str();
                const int port = client_ip_and_port.port();
                fprintf(stderr, "Info: Received shutdown from client IP=%s, port=%d\n", ip, port);
                shutdown_status = SSL_shutdown(ssl);
                if (1 == shutdown_status)
                {
                    fprintf(stderr, "DEBUG: SSL_shutdown() success.\n");
                    char outgoing_packet[1500];
                    const int max_packet_bytes = sizeof(outgoing_packet);
                    int packet_len = BIO_read(p->m_outgoing_bio, outgoing_packet, max_packet_bytes);
                    if (packet_len <= 0) {
                        continue;
                    }
                    socket.send_to(asio::buffer(outgoing_packet, packet_len), client_ip_and_port, 0, err_code_send);
                }
                else
                {
                    fprintf(stderr, "DEBUG: LINE=%d\n", __LINE__);
                    fprintf(stderr, "WARNING: SSL_shutdown() returns 0x%X\n", shutdown_status);
                }
fprintf(stderr, "DEBUG: LINE=%d\n", __LINE__);
                SSL_free(ssl);
                // 备注: 函数 SSL_free() 内部自动释放两条 BIO 内存缓冲区, 因此无需手动释放下列指针指向的 BIO 对象
                // 备注: BIO_free(p->m_incoming_bio);
                // 备注: BIO_free(p->m_outgoing_bio);

fprintf(stderr, "DEBUG: LINE=%d\n", __LINE__);
                connected_peers.erase(client_ip_and_port);
fprintf(stderr, "DEBUG: LINE=%d\n", __LINE__);
                fprintf(stderr, "Info: peer %s:%d has been removed from hash table\n", ip, port);
            }
            continue;
        }
        if (plaintext_len > 0) {
            fprintf(stdout, "DEBUG: %d bytes = {\n", plaintext_len);
            for (int i=0; i<plaintext_len; i++) {
                fprintf(stdout, "%c", char_from_int(plaintext[i]));
            }
            if ('\n' != plaintext[plaintext_len-1]) {
                fprintf(stdout, "\n");
            }
            fprintf(stdout, "}\n");
        }
        if (plaintext_len > 0 && SSL_write(p->m_ssl, plaintext, plaintext_len) > 0){
            char ciphertext[2000];
            const int max_ciphertext_bytes = sizeof(ciphertext);
            int ciphertext_len;
            ciphertext_len = BIO_ctrl_pending(p->m_outgoing_bio);
fprintf(stderr, "DEBUG: LINE=%d,  ciphertext_len = %d\n", __LINE__, ciphertext_len);
            if (ciphertext_len <= 0) {
                /* in theory an ok thing */
                continue;
            }
            if (ciphertext_len > max_ciphertext_bytes) {
                ciphertext_len = max_ciphertext_bytes;
            }
            ciphertext_len = BIO_read(p->m_outgoing_bio, ciphertext, ciphertext_len);
            socket.send_to(asio::buffer(ciphertext, ciphertext_len), client_ip_and_port, 0, err_code_send);

            int tmp;
            if ((tmp = BIO_ctrl_pending(p->m_outgoing_bio))>0) {
                fprintf(stderr, "DEBUG: LINE=%d, tmp = %d\n", __LINE__, tmp);

            }
        }
    }
    return 0;
}

static
void server_app_apply_default_configuation(ServerAppConf *conf)
{
    int ret;
    SSL_CTX *ctx;

    // SSL_load_error_strings();
    // SSL_library_init();

    ctx = SSL_CTX_new(DTLS_server_method());
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    ret = SSL_CTX_use_certificate_chain_file(ctx, "server-cert.pem");
    if (ret<=0)
    {
        fprintf(stderr, "ERROR: SSL_CTX_use_certificate_chain_file(ctx, server-cert.pem) returns %d\n", ret);
        goto errorcleanup;
        return;
    }
    ret = SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);
    if (ret<=0)
    {
        fprintf(stderr, "ERROR: SSL_CTX_use_PrivateKey_file(ctx, server-key.pem, SSL_FILETYPE_PEM) returns %d\n", ret);
        goto errorcleanup;
    }
    ret = SSL_CTX_check_private_key(ctx);
    if (ret<=0) {
        fprintf(stderr, "ERROR: public and private keys are incompatible!\n");
    }

    ret = SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384");
    if (ret<=0) {
        fprintf(stderr, "ERROR: failed to set the cipher list to the requested value!\n");
        fprintf(stderr, "ERROR: SSL_CTX_set_cipher_list() returns %d\n", ret);
        goto errorcleanup;
    }

    ret = SSL_CTX_load_verify_locations(ctx, "root-ca.pem", NULL);
    if (ret<=0)
    {
        fprintf(stderr, "ERROR: SSL_CTX_load_verify_locations -> %d\n", ret);
        goto errorcleanup;
    }
    ret = SSL_CTX_set_default_verify_file(ctx);
    if (ret<=0)
    {
        fprintf(stderr, "ERROR: SSL_CTX_set_default_verify_file -> %d\n", ret);
        goto errorcleanup;
    }

    SSL_CTX_set_read_ahead(ctx, 1);

    int (*verify_callback_fn)(int preverify_ok, X509_STORE_CTX *store_ctx);
    verify_callback_fn = NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback_fn);

    SSL_CTX_set_cookie_generate_cb(ctx, server_app_generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, server_app_verify_cookie);

    conf->ctx = ctx;
    return;

errorcleanup:
    SSL_CTX_free(ctx);
    conf->ctx = NULL;
    return;
}


#include <cctype>
static char char_from_int(int byte)
{
    if (isspace(byte) || isprint(byte)) {
        return ((char) byte);
    }
    return '?';
}

/* 这里暂时只使用固定不变的 DTLS cookie */
char cookie_str[] = "BISCUIT!";

static
int server_app_generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    memmove(cookie, cookie_str, sizeof(cookie_str)-1);
    *cookie_len = sizeof(cookie_str)-1;

    return 1;
}

static
int server_app_verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    return sizeof(cookie_str)-1==cookie_len && memcmp(cookie, cookie_str, sizeof(cookie_str)-1)==0;
}

// #include <openssl/evp.h>
// #include <openssl/rand.h>
//
// #define APP_COOKIE_SECRET_KEY_LENGTH 16
// char app_cookie_secret_key[APP_COOKIE_SECRET_KEY_LENGTH]={0};
// int app_is_cookie_secret_key_initialized = 0;
//
// #define APP_FEATURE_ENABLE_SM3 1
// #if defined(APP_FEATURE_ENABLE_SM3) && defined(OPENSSL_NO_SM3)
// #error "APP_FEATURE_ENABLE_SM3"// You must build customized OpenSSL with SM3 feture enabled!
// #endif
//
// #if defined(APP_FEATURE_ENABLE_SM3) && !defined(OPENSSL_NO_SM3)
// #define app_selected_hash_algorithm EVP_sm3()
// #else
// #define app_selected_hash_algorithm EVP_sha256()
// #endif
//
// static
// int server_app_generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
// {
//     BIO *bio = NULL;
//     custom_bio_data_t *cbiodata = NULL;
//     const unsigned char *src = NULL;
//     int n = 0;
//     unsigned char hmac_result[DTLS1_COOKIE_LENGTH] = {0}; // DTLS1_COOKIE_LENGTH = 256 但 DTLS v1.2 协议 (RFC 6347) 规定 cookie 长度的最大值为 255 字节(即2^8 -1)
//     unsigned int result_len = sizeof(hmac_result);
//
//     if (!app_is_cookie_secret_key_initialized)
//     {
//         if (!RAND_bytes(app_cookie_secret_key, APP_COOKIE_SECRET_KEY_LENGTH))
//         {
//             fprintf(stderr, "ERROR! Can not set random cookie secret key!\n");
//             return 0;
//         }
// 	    app_is_cookie_secret_key_initialized = 1;
// 	}
//
//     bio = SSL_get_wbio(ssl);
//     cbiodata = BIO_get_data(bio);
//     src = cbiodata->txaddr_buf.buf;
//     n = cbiodata->txaddr_buf.len;
//     result_len = sizeof(hmac_result);
//     HMAC(app_selected_hash_algorithm, app_cookie_secret_key, APP_COOKIE_SECRET_KEY_LENGTH, src, n, hmac_result, &result_len);
//     assert(result_len <= 255);
//     if (result_len > 255)
//     {
//         result_len = 255;
//     }
//     memcpy(cookie, hmac_result, (size_t)result_len);
//     *cookie_len = result_len;
//     return 1;
// }

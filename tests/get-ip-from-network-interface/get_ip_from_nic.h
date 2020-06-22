#ifndef GET_IP_FROM_NIC_H
#define GET_IP_FROM_NIC_H

#include <netinet/in.h>

/**
 * @brief get_ipv4_string_from_nic()
 * @brief get_ipv6_string_from_nic()
 *
 * @param outbuf
 * @param outbuf_len
 * @param nic_name 网卡名称字符串
 * @return 字符串
 */
const char *get_ipv4_string_from_nic(char outbuf[INET_ADDRSTRLEN], size_t _outbuf_len, const char nic_name[]);
const char *get_ipv6_string_from_nic(char outbuf[INET6_ADDRSTRLEN], size_t _outbuf_len, const char nic_name[]);

#endif // GET_IP_FROM_NIC_H

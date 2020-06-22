#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

const char *get_ipv4_string_from_nic(char _out_str[INET_ADDRSTRLEN], size_t _out_str_len, const char _nic_name[])
{
    //assert(NULL != _out_str);
    //assert(_out_str_len >= INET_ADDRSTRLEN);
    //assert(NULL != _nic_name);

    struct ifaddrs *array;
    struct ifaddrs *i;
    int family;
    const char *str = NULL;

    if (getifaddrs(&array) < 0) {
        perror("getifaddrs()");
        return NULL;
    }

    for (i = &array[0]; i != NULL; i = i->ifa_next) {
        if (NULL == i->ifa_addr) {
            continue;
        }

        if (0 != strcmp(i->ifa_name, _nic_name)) {
            /* 网卡名称不匹配, 直接跳过 */
            continue;
        }

        family = i->ifa_addr->sa_family;
        if (AF_INET != family) {
            continue;
        }

        struct sockaddr_in *sin = (void *)i->ifa_addr;
        str = inet_ntop(family, &sin->sin_addr, _out_str, (socklen_t)_out_str_len);
        if (NULL == str) {
            _out_str[0] = '\0';
        }
        break;
    }
    freeifaddrs(array);
    return str;
}

const char *get_ipv6_string_from_nic(char _out_str[INET6_ADDRSTRLEN], size_t _out_str_len, const char _nic_name[])
{
    //assert(NULL != _out_str);
    //assert(_out_str_len >= INET_ADDRSTRLEN);
    //assert(NULL != _nic_name);

    struct ifaddrs *array;
    struct ifaddrs *i;
    int family;
    const char *str = NULL;

    if (getifaddrs(&array) < 0) {
        perror("getifaddrs()");
        return NULL;
    }

    for (i = &array[0]; i != NULL; i = i->ifa_next) {
        if (NULL == i->ifa_addr) {
            continue;
        }

        if (0 != strcmp(i->ifa_name, _nic_name)) {
            /* 网卡名称不匹配, 直接跳过 */
            continue;
        }

        family = i->ifa_addr->sa_family;
        if (AF_INET6 != family) {
            continue;
        }

        struct sockaddr_in6 *sin6 = (void *)i->ifa_addr;
        str = inet_ntop(family, &sin6->sin6_addr, _out_str, (socklen_t)_out_str_len);
        if (NULL == str) {
            _out_str[0] = '\0';
        }
        break;
    }
    freeifaddrs(array);
    return str;
}

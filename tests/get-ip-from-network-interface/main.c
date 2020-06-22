#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if __STDC_VERSION__ >= 201112
#include <threads.h>
#endif

/**/
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h> /* Or #include <linux/ip.h> */
#include <netinet/udp.h> /* Or #include <linux/udp.h> */
#include <net/if.h>
#include <linux/if.h>

/**/
#include "xfs_name.h"
#include "xfs_mem.h"
#include "xfs_xisk.h"
#include "xfs_xsk.h"
#include "xfs_lcpu.h"
#include "queue/xfs_queue_parms.h"


static xfs_queue *ens33_rx_queue = NULL;
static xfs_queue *ens33_tx_queue = NULL;
static in_addr_t my_ipv4_addr = INADDR_ANY;
static __be16    my_udp_port = 0;

int echo_service_routine(void *args_not_used)
{
    (void) args_not_used;
    long int cnt;

    int err;
    void **pp;
    struct xfs_mbuf *rx_mbuf;
    struct xfs_mbuf *tx_mbuf;
    xfs_mbuf_pool *pool;
    const unsigned char *data;

    pp = (void*)&rx_mbuf;
    cnt = 0;
    while (cnt < 100) {
        data = NULL;
        rx_mbuf = NULL;
        err = ens33_rx_queue->dequeue(ens33_rx_queue, pp);
        if (err || NULL==rx_mbuf) {
            usleep(5*1000);//
            continue;
        }

        /* 检查mbuf */
        data = (void*)rx_mbuf;

        data += rx_mbuf->md.data_offset;
        /* 检查L2层: 是否IPv4报文? */
        const struct ethhdr *l2hdr;
        {
            l2hdr = (const void*)data;
            if (l2hdr->h_proto != htons(ETH_P_IP)) {
                // 不是IPv4报文: 直接忽略
                goto DELETE_RECEIVED_PACKET;
            }
        }

        data += ETH_HLEN;
        /* 检查L3层: IPv4地址是否一致? L3层中标注的4层协议号是否UDP? */
        const struct iphdr *l3hdr;
        {
            l3hdr = (const void*)data;
            //printf("l3hdr->version = %d\n", l3hdr->version);
            if (memcmp(&l3hdr->daddr, &my_ipv4_addr, sizeof(in_addr_t)) != 0) {
                // IP地址不匹配: 直接忽略
                goto DELETE_RECEIVED_PACKET;
            }
            if (l3hdr->protocol != IPPROTO_UDP) {
                // 不是UDP报文: 直接忽略
                goto DELETE_RECEIVED_PACKET;
            }
            data += (l3hdr->ihl * 4);
        }

        /* 检查L4层: UDP端口号 */
        const struct udphdr *l4hdr;
        {
            __le16 udplen=0;
            l4hdr = (const void*) data;
            //if (l4hdr->dest != my_udp_port) {
            //    // UDP端口号不匹配: 直接忽略
            //    goto DELETE_RECEIVED_PACKET;
            //}
            udplen = ntohs(l4hdr->len);
            if (udplen <= 0 || udplen > 1472) {
                // UDP报文长度异常: 直接忽略
                goto DELETE_RECEIVED_PACKET;
            }
            data += sizeof(struct udphdr);
        }

        pool = xfs_get_mbuf_pool(rx_mbuf);
        tx_mbuf = pool->alloc(pool);
        if (NULL == tx_mbuf) {
            goto DELETE_RECEIVED_PACKET;
        }
        {
            unsigned char *tx_data;
            struct iphdr *tx_iphdr;
            struct udphdr *tx_udphdr;

        memcpy(&tx_mbuf->hd_room[0], &rx_mbuf->hd_room[0], sizeof(tx_mbuf->hd_room));
        tx_mbuf->md.mbuf_size = rx_mbuf->md.mbuf_size;
        tx_mbuf->md.data_size = rx_mbuf->md.data_size;
        tx_mbuf->md.data_offset = rx_mbuf->md.data_offset;
        tx_mbuf->md.prot_type = htons(ETH_P_IP);
        tx_mbuf->md.tx_mtu = tx_mbuf->md.rx_mtu = 1500;
        tx_mbuf->md.flags =
                XFS_MBFLAG_TX_ETHHDR_DADDED //TX侧：目标MAC地址(已留空6字节)
                |XFS_MBFLAG_TX_ETHHDR_SADDED//TX侧：源MAC地址(已留空6字节)
                |XFS_MBFLAG_TX_PROTHDR_ADDED//TX侧：TCP,UDP头已填充
                |XFS_MBFLAG_TX_IPHDR_ADDED  //TX侧：IP头部已填充
                |XFS_MBFLAG_TX_IPHDR_CHECKED//TX侧：IP头部校验和已计算
                |XFS_MBFLAG_TX_PROT_CHECKED;//TX侧：TCP,UDP协议校验和已计算

            tx_data = (uint8_t *)tx_mbuf + tx_mbuf->md.data_offset;

            xfs_memzero(tx_data, ETH_HLEN); // Note: XISK不需要填写14字节MAC头,但要求留空14字节（xisk_thrd_tx.c内部某些冗余检查要求此处留空）
            tx_data += ETH_HLEN;

            tx_iphdr = (void *)(tx_data);
            tx_iphdr->ihl = l3hdr->ihl;
            tx_iphdr->version = 0x4;
            tx_iphdr->tos = l3hdr->tos;
            tx_iphdr->tot_len = l3hdr->tot_len;
            tx_iphdr->id = htons((uint16_t)cnt);
            tx_iphdr->frag_off = l3hdr->frag_off;
            tx_iphdr->ttl = l3hdr->ttl;
            tx_iphdr->protocol = IPPROTO_UDP;
            tx_iphdr->check = 0;/* IP校验和由硬件填充,假定物理网卡支持"ethtool -K ens33 tx on" */
            tx_iphdr->saddr = l3hdr->daddr;/* 对调 IP 地址 */
            tx_iphdr->daddr = l3hdr->saddr;/* 对调 IP 地址 */

            tx_data += tx_iphdr->ihl*4;
            tx_udphdr = (void *)(tx_data);
            tx_udphdr->len = l4hdr->len;
            tx_udphdr->dest = l4hdr->source;/* 对调 UDP 端口号 */
            tx_udphdr->source = l4hdr->dest;/* 对调 UDP 端口号 */
            tx_udphdr->check = 0x0000;/* UDP校验和留空(或由硬件填充:假定物理网卡支持"ethtool -K ens33 tx on") */

            tx_data += sizeof(struct udphdr);
            xfs_memcopy(tx_data, data, tx_udphdr->len - 8);

            /* 从tx队列发走UDP echo包 */
            err = ens33_tx_queue->enqueue(ens33_tx_queue, (void *)&tx_mbuf);
            if (XFS_QUEUE_FAILED == err) {
                xfs_mbuf_free(tx_mbuf);
                tx_mbuf = NULL;
                goto DELETE_RECEIVED_PACKET;
            }
            cnt++;
        }
DELETE_RECEIVED_PACKET:
        xfs_mbuf_free(rx_mbuf);
        rx_mbuf = NULL;
    }
    return 0;
}


void edit_server_ip_port(struct sockaddr_in *endpoint, int family, const char ipv4str[], in_port_t port_le16)
{
    endpoint->sin_family = (unsigned short int)family;
    endpoint->sin_port = htons(port_le16);
    inet_pton(family, ipv4str, &endpoint->sin_addr.s_addr);
}


void ethtool_enable_hw_tx_checksum_on_nic(const char nic[])
{
    char cmd[1024];

    XFS_ASSERT(NULL != nic && '\0' != nic[0]);
    snprintf(cmd, sizeof(cmd), "ethtool -K %s tx on rx on", nic);
    system(cmd);
}

#include "./get_ip_from_nic.h"

int main()
{
    struct sockaddr_in my_ip_port;
    char str_ipv4[INET_ADDRSTRLEN]="";
    char str_ipv6[INET6_ADDRSTRLEN]="";
    const char nic[] = "ens33";
    unsigned nic_index;

    // 启用网卡硬件TCP/IP校验和
    ethtool_enable_hw_tx_checksum_on_nic(nic);

    // 禁止本机向外发送ICMP(端口不可达)
    system("iptables -F");
    system("iptables -A OUTPUT -p icmp --icmp-type port-unreachable -j DROP");

    get_ipv4_string_from_nic(str_ipv4, INET_ADDRSTRLEN, nic);
    get_ipv6_string_from_nic(str_ipv6, INET6_ADDRSTRLEN, nic);
    printf("本机网卡名=%s, IPv4地址=%s\n", nic, str_ipv4);

    const __le16 MY_UDP_ECHO_SERVICE_PORT = 7;
    edit_server_ip_port(&my_ip_port, AF_INET, str_ipv4, MY_UDP_ECHO_SERVICE_PORT);

    xfs_xisk *xisk = NULL;
    xfs_xisk_conf isk_conf;
    xfs_name *mbuf_pool_name;
    xfs_mbuf_pool *mbuf_pool;

    xfs_name *isk_obj_name = xfs_make_name("w:%s", nic);
    if (NULL == isk_obj_name) {
        fprintf(stderr, "ERROR: xfs_make_name() failed!\n");
        fprintf(stderr, "       LINE=%d, FILE=%s\n", __LINE__, __FILE__);
        exit(EXIT_FAILURE);
    }

    nic_index = if_nametoindex(nic);
    if (0 == nic_index) {
        if (0 == nic_index) {
            fprintf(stderr, "ERROR: West NIC = %s does not exist!\n", nic);
        }
        exit(EXIT_FAILURE);
    }


    isk_conf.flags = 0;
    isk_conf.ifindex = (int)nic_index;
    isk_conf.rx_ring = 0;// RX队列号（xisk必须指定为0）
    isk_conf.tx_ring = 0;// TX队列号（xisk必须指定为0)
    long n_cpu_lcores;
    n_cpu_lcores = sysconf(_SC_NPROCESSORS_ONLN);
    if (n_cpu_lcores < 4) {
        fprintf(stderr, "ERROR: Total %ld CPU lcore(s) available, but we need at least %d!\n", n_cpu_lcores, 4);
        exit(EXIT_FAILURE);
    }
    isk_conf.rx_core = (int)n_cpu_lcores-1;// RX线程 CPU affinity
    isk_conf.tx_core = (int)n_cpu_lcores-2;// RX线程 CPU affinity
    isk_conf.rx_sched = XFS_LCPU_SCHED_COSHARING;//LCPU调度模式
    isk_conf.tx_sched = XFS_LCPU_SCHED_COSHARING;//LCPU调度模式
    isk_conf.xsk_rx_batch = 4;     // xsk_rx_batch: XSK套接字RX批量操作-每次批量接收最大建议值
    isk_conf.xsk_tx_batch = 4;     // xsk_tx_batch: XSK套接字TX批量发送-每次批量发送最大建议值
    isk_conf.xsk_frm_size = 4096;  // xsk_frm_size: XSK套接字RX/TX环数据帧大小，向上对齐到2的整数幂
    isk_conf.xsk_frm_nums = 128;   // xsk_frm_nums: XSK套接字RX/TX环数据帧数量，向上对齐到2的整数幂
    isk_conf.xsk_rq_size = XFS_QUEUE_CAPACITY_MIN; // xsk_rq_size: XSK套接字上行转发队列(rq)长度
    isk_conf.xsk_tq_size = XFS_QUEUE_CAPACITY_MIN; // xsk_tq_size: XSK套接字下行转发队列(tq)长度
    isk_conf.mbuf_pool = NULL;
    mbuf_pool_name = xfs_make_name("pktmbuf pool", nic);
    if (NULL == mbuf_pool_name) {
        fprintf(stderr, "ERROR: mbuf_pool_name is NULL\n");
        exit(EXIT_FAILURE);
    }
    mbuf_pool = xfs_new_mbuf_pool(mbuf_pool_name, isk_conf.xsk_frm_size, isk_conf.xsk_frm_nums*2);
    if (NULL == mbuf_pool) {
        fprintf(stderr, "ERROR: mbuf_pool is NULL\n");
        exit(EXIT_FAILURE);
    }
    isk_conf.mbuf_pool = mbuf_pool;

    xisk = xfs_new_xisk(isk_obj_name, &isk_conf);
    if (NULL == xisk) {
        fprintf(stderr, "ERROR: xfs_new_xisk() returns NULL\n");
        exit(EXIT_FAILURE);
    }
    ens33_rx_queue = xfs_xsk_rx_queue(xisk);
    ens33_tx_queue = xfs_xsk_tx_queue(xisk);
    XFS_ASSERT(NULL != ens33_rx_queue);
    XFS_ASSERT(NULL != ens33_tx_queue);
    my_udp_port = my_ip_port.sin_port;
    xfs_memcopy(&my_ipv4_addr, &my_ip_port.sin_addr.s_addr, sizeof(struct in_addr));

    thrd_t worker_thrd;
    thrd_create(&worker_thrd, echo_service_routine, NULL);
    thrd_detach(worker_thrd);

    sleep(1);
    xfs_xisk_start(xisk);
    sleep(5*60);//TODO

    do {
        //xfs_xisk_stop(xisk);
        //xfs_free_xisk(xisk);
        //xfs_free_mbuf_pool(mbuf_pool);
    } while(0);

    //xlog_device->set_file("./test.log", XLOG_DEVICE_NEW);
    //xlog_device->set_url("192.168.4.5", 9092, "ens38");
    //xlog_device->set_on();
    //xlog_device->set_off();
    return 0;
}

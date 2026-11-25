#pragma once
#include "../Tx10ubLinkMtu.h"
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define LWIP_IPV4 0
#define LWIP_ETHERNET 0
#define LWIP_ARP 0
#define LWIP_IPV6 1
#define LWIP_TCP 1
#define LWIP_UDP 0
#define LWIP_RAW 0
#define LWIP_ICMP 0
#define LWIP_ICMP6 1
#define LWIP_DHCP 0
#define LWIP_DNS 0
#define LWIP_IPV6_MLD 0
#define LWIP_IPV6_AUTOCONFIG 0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS 0
#define LWIP_IPV6_NUM_ADDRESSES 1
#define LWIP_IPV6_REASS 0
#define LWIP_IPV6_FRAG 0
#define LWIP_STATS 0
#define LWIP_NETIF_HOSTNAME 0
#define LWIP_NETIF_STATUS_CALLBACK 0
#define LWIP_NETIF_LINK_CALLBACK 0
#define MEM_ALIGNMENT 8
// Allow four simultaneous TCP owners to fill their send buffers while
// retaining receive reassembly and packet allocation headroom.
#define MEM_SIZE (896 * 1024)
#define MEMP_NUM_TCP_PCB 4
#define MEMP_NUM_TCP_SEG 1024
#define PBUF_POOL_SIZE 64
#define PBUF_POOL_BUFSIZE TX10UB_IPV6_MTU
#define TCP_MSS (TX10UB_IPV6_MTU - 40 - 20)
#define TCP_WND 32768
// Negotiate larger peer windows across AWDL ACK gaps. Our own receive
// window stays at 32 KiB and is advertised without a shift.
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 0
#define TCP_SND_BUF (128 * 1024)
#define TCP_SNDLOWAT 32767
#define TCP_SND_QUEUELEN 256
#define TCP_QUEUE_OOSEQ 1
#define TCP_OOSEQ_MAX_BYTES TCP_WND
#define TCP_OOSEQ_MAX_PBUFS 32
#define LWIP_TCP_TIMESTAMPS 1
#define LWIP_TCP_PARTIAL_ACK_RECOVERY 1
#define LWIP_TCP_KEEPALIVE 1
#define LWIP_MULTICAST_TX_OPTIONS 0
#define LWIP_HOOK_TCP_ISN(local_ip, local_port, remote_ip, remote_port) LWIP_RAND()

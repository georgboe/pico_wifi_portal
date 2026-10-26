#ifndef PICO_WIFI_PORTAL_EXAMPLES_LWIPOPTS_H
#define PICO_WIFI_PORTAL_EXAMPLES_LWIPOPTS_H

// lwIP configuration for the PicoWiFiPortal examples
// (pico_cyw43_arch_lwip_threadsafe_background or pico_cyw43_arch_lwip_poll).

#ifndef NO_SYS
#define NO_SYS 1
#endif
#ifndef LWIP_SOCKET
#define LWIP_SOCKET 0
#endif
#define LWIP_NETCONN 0

#if PICO_CYW43_ARCH_POLL
#define MEM_LIBC_MALLOC 1
#else
// MEM_LIBC_MALLOC is incompatible with non-polling versions.
#define MEM_LIBC_MALLOC 0
#endif
#define MEM_ALIGNMENT 4
#define MEM_SIZE 16000
#define MEMP_NUM_TCP_SEG 32
#define MEMP_NUM_ARP_QUEUE 10
#define MEMP_NUM_TCP_PCB 10
#define MEMP_NUM_UDP_PCB 8
// The portal page is sent from flash as PBUF_ROM segments.
#define MEMP_NUM_PBUF 32
#define PBUF_POOL_SIZE 24

#define LWIP_ARP 1
#define LWIP_ETHERNET 1
#define LWIP_ICMP 1
#define LWIP_RAW 1
#define LWIP_IPV4 1
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_DNS 1
#define LWIP_DHCP 1
#define LWIP_TCP_KEEPALIVE 1
#define LWIP_NETIF_HOSTNAME 1
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_LINK_CALLBACK 1
#define LWIP_NETIF_TX_SINGLE_PBUF 1
#define LWIP_CHKSUM_ALGORITHM 3
#define DHCP_DOES_ARP_CHECK 0
#define LWIP_DHCP_DOES_ACD_CHECK 0

#define TCP_MSS 1460
#define TCP_WND (8 * TCP_MSS)
#define TCP_SND_BUF (8 * TCP_MSS)
#define TCP_SND_QUEUELEN ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))

#ifndef NDEBUG
#define LWIP_DEBUG 1
#define LWIP_STATS 1
#define LWIP_STATS_DISPLAY 1
#endif

#endif

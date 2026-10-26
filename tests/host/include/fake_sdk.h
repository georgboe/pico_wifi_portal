#pragma once

// Host stand-in for the parts of the Pico SDK, CYW43 driver and lwIP raw API
// that PicoWiFiPortal uses. Every SDK header path the library includes maps
// to this file. Behaviour and failure injection live in FakePico.h/.cpp.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

// --- lwipopts -------------------------------------------------------------

#define LWIP_IPV4 1
#define LWIP_UDP 1
#define LWIP_TCP 1
#define LWIP_DHCP 1
#define LWIP_DNS 1
#define LWIP_NETIF_HOSTNAME 1

// --- pico/stdlib, pico/time -----------------------------------------------

#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES (2u * 1024u * 1024u)
#endif

#define PICO_OK 0
#define PICO_ERROR_TIMEOUT (-1)
#define PICO_ERROR_GENERIC (-2)

typedef uint64_t absolute_time_t;

absolute_time_t get_absolute_time();
uint32_t to_ms_since_boot(absolute_time_t time);
absolute_time_t make_timeout_time_ms(uint32_t ms);
static inline void tight_loop_contents() {}

// --- hardware/flash, pico/flash -------------------------------------------

extern "C" uint8_t pwp_fake_flash[];
#define XIP_BASE (reinterpret_cast<uintptr_t>(pwp_fake_flash))
#define FLASH_SECTOR_SIZE 4096u
#define FLASH_PAGE_SIZE 256u

void flash_range_erase(uint32_t flash_offs, size_t count);
void flash_range_program(uint32_t flash_offs, const uint8_t* data, size_t count);
int flash_safe_execute(void (*func)(void*), void* param, uint32_t enter_exit_timeout_ms);

// --- hardware/clocks, hardware/watchdog, pico/unique_id -------------------

enum clock_index { clk_sys = 5 };
uint32_t clock_get_hz(enum clock_index clk_index);

// Throws FakeReboot (see FakePico.h) so tests can observe the reboot.
void watchdog_reboot(uint32_t pc, uint32_t sp, uint32_t delay_ms);

#define PICO_UNIQUE_BOARD_ID_SIZE_BYTES 8
void pico_get_unique_board_id_string(char* id_out, unsigned len);

// --- lwip/err, lwip/def, lwip/ip_addr -------------------------------------

typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
typedef int8_t err_t;

enum {
  ERR_OK = 0,
  ERR_MEM = -1,
  ERR_BUF = -2,
  ERR_TIMEOUT = -3,
  ERR_RTE = -4,
  ERR_INPROGRESS = -5,
  ERR_VAL = -6,
  ERR_WOULDBLOCK = -7,
  ERR_USE = -8,
  ERR_ALREADY = -9,
  ERR_ISCONN = -10,
  ERR_CONN = -11,
  ERR_IF = -12,
  ERR_ABRT = -13,
  ERR_RST = -14,
  ERR_CLSD = -15,
  ERR_ARG = -16
};

uint32_t lwip_htonl(uint32_t value);
uint32_t lwip_ntohl(uint32_t value);

struct ip4_addr {
  uint32_t addr;  // Network byte order, as in lwIP.
};
typedef struct ip4_addr ip4_addr_t;
// IPv4-only lwIP build: ip_addr_t is ip4_addr_t.
typedef ip4_addr_t ip_addr_t;

#define IPADDR_TYPE_V4 0U
#define ip_addr_copy_from_ip4(dest, src) ((dest) = (src))

extern const ip_addr_t pwp_fake_ip_addr_any;
extern const ip_addr_t pwp_fake_ip_addr_broadcast;
#define IP_ANY_TYPE (&pwp_fake_ip_addr_any)
#define IP_ADDR_BROADCAST (&pwp_fake_ip_addr_broadcast)

// --- lwip/netif, lwip/dhcp, lwip/dns --------------------------------------

struct netif {
  ip4_addr_t ip_addr;
  ip4_addr_t netmask;
  ip4_addr_t gw;
  const char* hostname;
  bool dhcpStarted;
};

const ip4_addr_t* netif_ip4_addr(const struct netif* netif);
const ip4_addr_t* netif_ip4_netmask(const struct netif* netif);
const ip4_addr_t* netif_ip4_gw(const struct netif* netif);
void netif_set_addr(struct netif* netif, const ip4_addr_t* ipaddr,
                    const ip4_addr_t* netmask, const ip4_addr_t* gw);
void netif_set_default(struct netif* netif);
void netif_set_hostname(struct netif* netif, const char* name);

err_t dhcp_start(struct netif* netif);
void dhcp_release_and_stop(struct netif* netif);
void dns_setserver(u8_t numdns, const ip_addr_t* dnsserver);

// --- lwip/pbuf ------------------------------------------------------------

enum pbuf_layer { PBUF_TRANSPORT = 74 };
enum pbuf_type { PBUF_RAM = 0x280 };

struct pbuf {
  struct pbuf* next;
  void* payload;
  u16_t tot_len;
  u16_t len;
};

struct pbuf* pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type);
u8_t pbuf_free(struct pbuf* p);
err_t pbuf_take(struct pbuf* buf, const void* dataptr, u16_t len);
u16_t pbuf_copy_partial(const struct pbuf* buf, void* dataptr, u16_t len,
                        u16_t offset);

// --- lwip/udp -------------------------------------------------------------

struct udp_pcb;
typedef void (*udp_recv_fn)(void* arg, struct udp_pcb* pcb, struct pbuf* p,
                            const ip_addr_t* addr, u16_t port);

#define SOF_BROADCAST 0x20U

struct udp_pcb {
  int fakeState;  // FakeUdpState
  u8_t so_options;
  const struct netif* boundNetif;
  u16_t localPort;
  udp_recv_fn recv;
  void* recvArg;
};

#define ip_set_option(pcb, opt) ((pcb)->so_options |= (opt))

struct udp_pcb* udp_new_ip_type(u8_t type);
void udp_bind_netif(struct udp_pcb* pcb, const struct netif* netif);
err_t udp_bind(struct udp_pcb* pcb, const ip_addr_t* ipaddr, u16_t port);
void udp_recv(struct udp_pcb* pcb, udp_recv_fn recv, void* recv_arg);
void udp_remove(struct udp_pcb* pcb);
err_t udp_sendto_if(struct udp_pcb* pcb, struct pbuf* p,
                    const ip_addr_t* dst_ip, u16_t dst_port,
                    struct netif* netif);

// --- lwip/tcp -------------------------------------------------------------

struct tcp_pcb;
typedef err_t (*tcp_accept_fn)(void* arg, struct tcp_pcb* newpcb, err_t err);
typedef err_t (*tcp_recv_fn)(void* arg, struct tcp_pcb* tpcb, struct pbuf* p,
                             err_t err);
typedef err_t (*tcp_sent_fn)(void* arg, struct tcp_pcb* tpcb, u16_t len);
typedef err_t (*tcp_poll_fn)(void* arg, struct tcp_pcb* tpcb);
typedef void (*tcp_err_fn)(void* arg, err_t err);

#define TCP_WRITE_FLAG_COPY 0x01

struct tcp_pcb;

struct tcp_pcb* tcp_new_ip_type(u8_t type);
void tcp_bind_netif(struct tcp_pcb* pcb, const struct netif* netif);
err_t tcp_bind(struct tcp_pcb* pcb, const ip_addr_t* ipaddr, u16_t port);
struct tcp_pcb* tcp_listen_with_backlog(struct tcp_pcb* pcb, u8_t backlog);
void tcp_arg(struct tcp_pcb* pcb, void* arg);
void tcp_accept(struct tcp_pcb* pcb, tcp_accept_fn accept);
void tcp_recv(struct tcp_pcb* pcb, tcp_recv_fn recv);
void tcp_sent(struct tcp_pcb* pcb, tcp_sent_fn sent);
void tcp_err(struct tcp_pcb* pcb, tcp_err_fn err);
void tcp_poll(struct tcp_pcb* pcb, tcp_poll_fn poll, u8_t interval);
void tcp_recved(struct tcp_pcb* pcb, u16_t len);
u16_t tcp_sndbuf(const struct tcp_pcb* pcb);
err_t tcp_write(struct tcp_pcb* pcb, const void* dataptr, u16_t len,
                u8_t apiflags);
err_t tcp_output(struct tcp_pcb* pcb);
err_t tcp_close(struct tcp_pcb* pcb);
void tcp_abort(struct tcp_pcb* pcb);

// --- cyw43 / pico/cyw43_arch ----------------------------------------------

#define CYW43_ITF_STA 0
#define CYW43_ITF_AP 1

#define CYW43_LINK_DOWN 0
#define CYW43_LINK_JOIN 1
#define CYW43_LINK_NOIP 2
#define CYW43_LINK_UP 3
#define CYW43_LINK_FAIL (-1)
#define CYW43_LINK_NONET (-2)
#define CYW43_LINK_BADAUTH (-3)

#define CYW43_AUTH_OPEN 0
#define CYW43_AUTH_WPA2_AES_PSK 0x00400004

typedef struct _cyw43_ev_scan_result_t {
  uint8_t bssid[6];
  uint8_t ssid_len;
  uint8_t ssid[32];
  uint16_t channel;
  uint8_t auth_mode;
  int16_t rssi;
} cyw43_ev_scan_result_t;

typedef struct _cyw43_wifi_scan_options_t {
  uint32_t version;
  uint16_t duration;
  uint16_t channel_num;
  uint16_t channel_list[1];
  uint8_t ssid_len;
  uint8_t ssid[32];
  uint8_t scan_type;
} cyw43_wifi_scan_options_t;

typedef struct _cyw43_t {
  uint8_t itf_state;
  struct netif netif[2];
} cyw43_t;

extern cyw43_t cyw43_state;

bool cyw43_is_initialized(cyw43_t* self);
void cyw43_arch_enable_sta_mode();
void cyw43_arch_enable_ap_mode(const char* ssid, const char* password,
                               uint32_t auth);
void cyw43_arch_disable_ap_mode();
void cyw43_wifi_ap_set_channel(cyw43_t* self, uint32_t channel);
int cyw43_wifi_scan(cyw43_t* self, cyw43_wifi_scan_options_t* opts, void* env,
                    int (*result_cb)(void*, const cyw43_ev_scan_result_t*));
bool cyw43_wifi_scan_active(cyw43_t* self);
int cyw43_wifi_get_mac(cyw43_t* self, int itf, uint8_t mac[6]);
int cyw43_arch_wifi_connect_async(const char* ssid, const char* pw,
                                  uint32_t auth);
int cyw43_wifi_leave(cyw43_t* self, int itf);
int cyw43_tcpip_link_status(cyw43_t* self, int itf);
void cyw43_arch_poll();
void cyw43_arch_wait_for_work_until(absolute_time_t until);
void cyw43_arch_lwip_begin();
void cyw43_arch_lwip_end();

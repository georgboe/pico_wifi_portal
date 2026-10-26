#include "FakePico.h"

#include <malloc.h>

#include <algorithm>
#include <cstdlib>

#include "TestAssert.h"

// --- Linker symbols -----------------------------------------------------------

extern "C" {
alignas(4096) uint8_t pwp_fake_flash[PICO_FLASH_SIZE_BYTES];
uint8_t pwp_fake_ram[16];
}

#define PWP_STRINGIFY_(value) #value
#define PWP_STRINGIFY(value) PWP_STRINGIFY_(value)

// The library takes the addresses of these SDK linker symbols. Place them so
// that &__flash_binary_end - XIP_BASE == kFakeBinaryEndOffset and the heap
// span is kFakeHeapTotal bytes.
asm(".globl __flash_binary_end\n"
    ".set __flash_binary_end, pwp_fake_flash + 0x10000\n"
    ".globl __bss_end__\n"
    ".set __bss_end__, pwp_fake_ram\n"
    ".globl __StackLimit\n"
    ".set __StackLimit, pwp_fake_ram + 262144\n");
static_assert(kFakeBinaryEndOffset == 0x10000, "Update the asm above");
static_assert(kFakeHeapTotal == 262144, "Update the asm above");

// --- State --------------------------------------------------------------------

uint32_t FakeMillis = 0;
FakeFlashState FakeFlash;
FakeCyw43State FakeCyw43;
FakeLwipState FakeLwip;
size_t FakeHeapUsed = 131072;
cyw43_t cyw43_state;

const ip_addr_t pwp_fake_ip_addr_any = {0};
const ip_addr_t pwp_fake_ip_addr_broadcast = {0xFFFFFFFFUL};

namespace {

void requireLock(const char* function) {
  if (FakeLwip.lockDepth > 0) return;
  std::fprintf(stderr, "%s called without the lwIP lock\n", function);
  std::abort();
}

void requireLiveTcp(const tcp_pcb* pcb, const char* function) {
  if (pcb && (pcb->state == FakeTcpState::Active ||
              pcb->state == FakeTcpState::Listening)) {
    return;
  }
  std::fprintf(stderr, "%s called on a closed/freed tcp_pcb\n", function);
  std::abort();
}

void requireLiveUdp(const udp_pcb* pcb, const char* function) {
  if (pcb && pcb->fakeState == FakeUdpActive) return;
  std::fprintf(stderr, "%s called on a removed udp_pcb\n", function);
  std::abort();
}

struct LockScope {
  LockScope() { ++FakeLwip.lockDepth; }
  ~LockScope() { --FakeLwip.lockDepth; }
};

}  // namespace

// --- Time ---------------------------------------------------------------------

absolute_time_t get_absolute_time() {
  return static_cast<absolute_time_t>(FakeMillis) * 1000ULL;
}

uint32_t to_ms_since_boot(absolute_time_t time) {
  return static_cast<uint32_t>(time / 1000ULL);
}

absolute_time_t make_timeout_time_ms(uint32_t ms) {
  return get_absolute_time() + static_cast<absolute_time_t>(ms) * 1000ULL;
}

// --- Flash --------------------------------------------------------------------

uint8_t* fakeFlashAt(uint32_t offset) {
  assert(offset < PICO_FLASH_SIZE_BYTES);
  return pwp_fake_flash + offset;
}

void flash_range_erase(uint32_t flash_offs, size_t count) {
  assert(flash_offs % FLASH_SECTOR_SIZE == 0);
  assert(count % FLASH_SECTOR_SIZE == 0);
  assert(flash_offs + count <= PICO_FLASH_SIZE_BYTES);
  ++FakeFlash.eraseCalls;
  for (size_t i = 0; i < count; ++i) {
    if (FakeFlash.eraseByteBudget == 0) return;
    if (FakeFlash.eraseByteBudget > 0) --FakeFlash.eraseByteBudget;
    pwp_fake_flash[flash_offs + i] = 0xFF;
  }
}

void flash_range_program(uint32_t flash_offs, const uint8_t* data,
                         size_t count) {
  assert(flash_offs % FLASH_PAGE_SIZE == 0);
  assert(count % FLASH_PAGE_SIZE == 0);
  assert(flash_offs + count <= PICO_FLASH_SIZE_BYTES);
  ++FakeFlash.programCalls;
  for (size_t i = 0; i < count; ++i) {
    if (FakeFlash.programByteBudget == 0) return;
    if (FakeFlash.programByteBudget > 0) --FakeFlash.programByteBudget;
    // NOR flash programming can only clear bits.
    pwp_fake_flash[flash_offs + i] &= data[i];
  }
}

int flash_safe_execute(void (*func)(void*), void* param,
                       uint32_t enter_exit_timeout_ms) {
  (void)enter_exit_timeout_ms;
  ++FakeFlash.safeExecuteCalls;
  if (FakeFlash.failSafeExecute > 0) {
    --FakeFlash.failSafeExecute;
    return PICO_ERROR_TIMEOUT;
  }
  func(param);
  return PICO_OK;
}

// --- Misc SDK -----------------------------------------------------------------

uint32_t clock_get_hz(enum clock_index clk_index) {
  assert(clk_index == clk_sys);
  return 125000000UL;
}

void watchdog_reboot(uint32_t pc, uint32_t sp, uint32_t delay_ms) {
  (void)pc;
  (void)sp;
  (void)delay_ms;
  ++FakeCyw43.rebootCalls;
  throw FakeReboot{};
}

void pico_get_unique_board_id_string(char* id_out, unsigned len) {
  std::snprintf(id_out, len, "%s", "E6614103E7452D2F");
}

struct mallinfo mallinfo() {
  struct mallinfo info;
  info.uordblks = FakeHeapUsed;
  return info;
}

// --- lwIP basics ----------------------------------------------------------------

uint32_t lwip_htonl(uint32_t value) {
  return ((value & 0xFFU) << 24) | ((value & 0xFF00U) << 8) |
         ((value >> 8) & 0xFF00U) | (value >> 24);
}

uint32_t lwip_ntohl(uint32_t value) { return lwip_htonl(value); }

const ip4_addr_t* netif_ip4_addr(const struct netif* netif) {
  return &netif->ip_addr;
}

const ip4_addr_t* netif_ip4_netmask(const struct netif* netif) {
  return &netif->netmask;
}

const ip4_addr_t* netif_ip4_gw(const struct netif* netif) {
  return &netif->gw;
}

void netif_set_addr(struct netif* netif, const ip4_addr_t* ipaddr,
                    const ip4_addr_t* netmask, const ip4_addr_t* gw) {
  requireLock("netif_set_addr");
  netif->ip_addr = *ipaddr;
  netif->netmask = *netmask;
  netif->gw = *gw;
  if (netif == fakeApNetif() && FakeLwip.apAddressOverride) {
    netif->ip_addr.addr = lwip_htonl(FakeLwip.apAddressOverrideValue);
  }
}

void netif_set_default(struct netif* netif) {
  requireLock("netif_set_default");
  FakeLwip.defaultNetif = netif;
}

void netif_set_hostname(struct netif* netif, const char* name) {
  requireLock("netif_set_hostname");
  netif->hostname = name;
}

err_t dhcp_start(struct netif* netif) {
  requireLock("dhcp_start");
  ++FakeLwip.dhcpStartCalls;
  if (FakeLwip.dhcpStartResult == ERR_OK) netif->dhcpStarted = true;
  return FakeLwip.dhcpStartResult;
}

void dhcp_release_and_stop(struct netif* netif) {
  requireLock("dhcp_release_and_stop");
  ++FakeLwip.dhcpStopCalls;
  netif->dhcpStarted = false;
}

void dns_setserver(u8_t numdns, const ip_addr_t* dnsserver) {
  requireLock("dns_setserver");
  assert(numdns < 2);
  FakeLwip.dnsServers[numdns] = *dnsserver;
}

// --- pbuf -----------------------------------------------------------------------

struct pbuf* pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type) {
  (void)layer;
  (void)type;
  struct pbuf* p = new pbuf;
  p->next = nullptr;
  p->payload = new uint8_t[length > 0 ? length : 1]();
  p->tot_len = length;
  p->len = length;
  ++FakeLwip.livePbufs;
  return p;
}

u8_t pbuf_free(struct pbuf* p) {
  assert(p != nullptr);
  delete[] static_cast<uint8_t*>(p->payload);
  delete p;
  --FakeLwip.livePbufs;
  return 1;
}

err_t pbuf_take(struct pbuf* buf, const void* dataptr, u16_t len) {
  if (len > buf->tot_len) return ERR_ARG;
  std::memcpy(buf->payload, dataptr, len);
  return ERR_OK;
}

u16_t pbuf_copy_partial(const struct pbuf* buf, void* dataptr, u16_t len,
                        u16_t offset) {
  if (offset >= buf->tot_len) return 0;
  const u16_t count = std::min<u16_t>(len, buf->tot_len - offset);
  std::memcpy(dataptr, static_cast<const uint8_t*>(buf->payload) + offset,
              count);
  return count;
}

// --- UDP ------------------------------------------------------------------------

struct udp_pcb* udp_new_ip_type(u8_t type) {
  requireLock("udp_new_ip_type");
  assert(type == IPADDR_TYPE_V4);
  if (FakeLwip.udpNewFails) return nullptr;
  FakeLwip.udpPcbs.push_back(udp_pcb{FakeUdpActive, 0, nullptr, 0, nullptr,
                                     nullptr});
  return &FakeLwip.udpPcbs.back();
}

void udp_bind_netif(struct udp_pcb* pcb, const struct netif* netif) {
  requireLock("udp_bind_netif");
  requireLiveUdp(pcb, "udp_bind_netif");
  pcb->boundNetif = netif;
}

err_t udp_bind(struct udp_pcb* pcb, const ip_addr_t* ipaddr, u16_t port) {
  requireLock("udp_bind");
  requireLiveUdp(pcb, "udp_bind");
  (void)ipaddr;
  if (FakeLwip.udpBindResult != ERR_OK &&
      (FakeLwip.udpBindFailPort == 0 || FakeLwip.udpBindFailPort == port)) {
    return FakeLwip.udpBindResult;
  }
  pcb->localPort = port;
  return ERR_OK;
}

void udp_recv(struct udp_pcb* pcb, udp_recv_fn recv, void* recv_arg) {
  requireLock("udp_recv");
  requireLiveUdp(pcb, "udp_recv");
  pcb->recv = recv;
  pcb->recvArg = recv_arg;
}

void udp_remove(struct udp_pcb* pcb) {
  requireLock("udp_remove");
  requireLiveUdp(pcb, "udp_remove");
  pcb->fakeState = FakeUdpRemoved;
  pcb->recv = nullptr;
  pcb->recvArg = nullptr;
}

err_t udp_sendto_if(struct udp_pcb* pcb, struct pbuf* p,
                    const ip_addr_t* dst_ip, u16_t dst_port,
                    struct netif* netif) {
  requireLock("udp_sendto_if");
  requireLiveUdp(pcb, "udp_sendto_if");
  FakeUdpPacket packet;
  const uint8_t* data = static_cast<const uint8_t*>(p->payload);
  packet.data.assign(data, data + p->tot_len);
  packet.address = dst_ip ? lwip_ntohl(dst_ip->addr) : 0;
  packet.port = dst_port;
  packet.netif = netif;
  FakeLwip.udpSent.push_back(packet);
  return ERR_OK;
}

udp_pcb* fakeUdpPcb(u16_t port) {
  for (udp_pcb& pcb : FakeLwip.udpPcbs) {
    if (pcb.fakeState == FakeUdpActive && pcb.localPort == port) return &pcb;
  }
  return nullptr;
}

bool fakeUdpDeliver(u16_t port, const std::vector<uint8_t>& data,
                    uint32_t sourceAddress, u16_t sourcePort) {
  udp_pcb* pcb = fakeUdpPcb(port);
  if (!pcb || !pcb->recv) return false;
  LockScope lock;
  struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(data.size()),
                              PBUF_RAM);
  std::memcpy(p->payload, data.data(), data.size());
  const ip_addr_t source = {lwip_htonl(sourceAddress)};
  pcb->recv(pcb->recvArg, pcb, p, &source, sourcePort);
  return true;
}

// --- TCP ------------------------------------------------------------------------

struct tcp_pcb* tcp_new_ip_type(u8_t type) {
  requireLock("tcp_new_ip_type");
  assert(type == IPADDR_TYPE_V4);
  if (FakeLwip.tcpNewFails) return nullptr;
  FakeLwip.tcpPcbs.emplace_back();
  FakeLwip.tcpPcbs.back().sndbuf = FakeLwip.defaultSndBuf;
  return &FakeLwip.tcpPcbs.back();
}

void tcp_bind_netif(struct tcp_pcb* pcb, const struct netif* netif) {
  requireLock("tcp_bind_netif");
  requireLiveTcp(pcb, "tcp_bind_netif");
  pcb->boundNetif = netif;
}

err_t tcp_bind(struct tcp_pcb* pcb, const ip_addr_t* ipaddr, u16_t port) {
  requireLock("tcp_bind");
  requireLiveTcp(pcb, "tcp_bind");
  (void)ipaddr;
  if (FakeLwip.tcpBindResult != ERR_OK) return FakeLwip.tcpBindResult;
  pcb->localPort = port;
  return ERR_OK;
}

struct tcp_pcb* tcp_listen_with_backlog(struct tcp_pcb* pcb, u8_t backlog) {
  requireLock("tcp_listen_with_backlog");
  requireLiveTcp(pcb, "tcp_listen_with_backlog");
  (void)backlog;
  if (FakeLwip.tcpListenFails) return nullptr;
  // Like lwIP, the original pcb is freed and a listen pcb returned.
  FakeLwip.tcpPcbs.emplace_back();
  tcp_pcb& listener = FakeLwip.tcpPcbs.back();
  listener.state = FakeTcpState::Listening;
  listener.boundNetif = pcb->boundNetif;
  listener.localPort = pcb->localPort;
  pcb->state = FakeTcpState::Freed;
  return &listener;
}

void tcp_arg(struct tcp_pcb* pcb, void* arg) {
  requireLock("tcp_arg");
  requireLiveTcp(pcb, "tcp_arg");
  pcb->arg = arg;
}

void tcp_accept(struct tcp_pcb* pcb, tcp_accept_fn accept) {
  requireLock("tcp_accept");
  requireLiveTcp(pcb, "tcp_accept");
  pcb->accept = accept;
}

void tcp_recv(struct tcp_pcb* pcb, tcp_recv_fn recv) {
  requireLock("tcp_recv");
  requireLiveTcp(pcb, "tcp_recv");
  pcb->recv = recv;
}

void tcp_sent(struct tcp_pcb* pcb, tcp_sent_fn sent) {
  requireLock("tcp_sent");
  requireLiveTcp(pcb, "tcp_sent");
  pcb->sent = sent;
}

void tcp_err(struct tcp_pcb* pcb, tcp_err_fn err) {
  requireLock("tcp_err");
  requireLiveTcp(pcb, "tcp_err");
  pcb->err = err;
}

void tcp_poll(struct tcp_pcb* pcb, tcp_poll_fn poll, u8_t interval) {
  requireLock("tcp_poll");
  requireLiveTcp(pcb, "tcp_poll");
  pcb->poll = poll;
  pcb->pollInterval = interval;
}

void tcp_recved(struct tcp_pcb* pcb, u16_t len) {
  requireLock("tcp_recved");
  requireLiveTcp(pcb, "tcp_recved");
  pcb->recvedBytes += len;
}

u16_t tcp_sndbuf(const struct tcp_pcb* pcb) {
  requireLock("tcp_sndbuf");
  requireLiveTcp(pcb, "tcp_sndbuf");
  return pcb->sndbuf;
}

err_t tcp_write(struct tcp_pcb* pcb, const void* dataptr, u16_t len,
                u8_t apiflags) {
  requireLock("tcp_write");
  requireLiveTcp(pcb, "tcp_write");
  (void)apiflags;
  if (len > pcb->sndbuf) return ERR_MEM;
  pcb->written.append(static_cast<const char*>(dataptr), len);
  pcb->sndbuf = static_cast<u16_t>(pcb->sndbuf - len);
  return ERR_OK;
}

err_t tcp_output(struct tcp_pcb* pcb) {
  requireLock("tcp_output");
  requireLiveTcp(pcb, "tcp_output");
  ++pcb->outputCalls;
  return ERR_OK;
}

err_t tcp_close(struct tcp_pcb* pcb) {
  requireLock("tcp_close");
  requireLiveTcp(pcb, "tcp_close");
  if (FakeLwip.tcpCloseResult != ERR_OK) return FakeLwip.tcpCloseResult;
  pcb->state = FakeTcpState::Closed;
  return ERR_OK;
}

void tcp_abort(struct tcp_pcb* pcb) {
  requireLock("tcp_abort");
  requireLiveTcp(pcb, "tcp_abort");
  pcb->state = FakeTcpState::Aborted;
  // lwIP reports the abort through the error callback.
  if (pcb->err) pcb->err(pcb->arg, ERR_ABRT);
}

tcp_pcb* fakeTcpListener(u16_t port) {
  for (tcp_pcb& pcb : FakeLwip.tcpPcbs) {
    if (pcb.state == FakeTcpState::Listening && pcb.localPort == port) {
      return &pcb;
    }
  }
  return nullptr;
}

tcp_pcb* fakeTcpConnect(u16_t port) {
  tcp_pcb* listener = fakeTcpListener(port);
  if (!listener || !listener->accept) return nullptr;
  FakeLwip.tcpPcbs.emplace_back();
  tcp_pcb* client = &FakeLwip.tcpPcbs.back();
  client->sndbuf = FakeLwip.defaultSndBuf;
  client->localPort = port;
  LockScope lock;
  const err_t result = listener->accept(listener->arg, client, ERR_OK);
  if (result != ERR_OK) return nullptr;
  return client;
}

err_t fakeTcpSend(tcp_pcb* pcb, const std::string& data) {
  requireLiveTcp(pcb, "fakeTcpSend");
  assert(pcb->recv != nullptr);
  LockScope lock;
  struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(data.size()),
                              PBUF_RAM);
  std::memcpy(p->payload, data.data(), data.size());
  return pcb->recv(pcb->arg, pcb, p, ERR_OK);
}

err_t fakeTcpRemoteClose(tcp_pcb* pcb) {
  requireLiveTcp(pcb, "fakeTcpRemoteClose");
  if (!pcb->recv) return ERR_OK;
  LockScope lock;
  return pcb->recv(pcb->arg, pcb, nullptr, ERR_OK);
}

err_t fakeTcpAck(tcp_pcb* pcb, u16_t len) {
  requireLiveTcp(pcb, "fakeTcpAck");
  pcb->sndbuf = static_cast<u16_t>(pcb->sndbuf + len);
  if (!pcb->sent) return ERR_OK;
  LockScope lock;
  return pcb->sent(pcb->arg, pcb, len);
}

err_t fakeTcpPoll(tcp_pcb* pcb) {
  requireLiveTcp(pcb, "fakeTcpPoll");
  if (!pcb->poll) return ERR_OK;
  LockScope lock;
  return pcb->poll(pcb->arg, pcb);
}

FakeHttpResponse parseHttpResponse(const std::string& raw) {
  FakeHttpResponse response;
  const size_t headerEnd = raw.find("\r\n\r\n");
  if (headerEnd == std::string::npos) return response;
  const size_t statusStart = raw.find(' ');
  if (statusStart == std::string::npos) return response;
  response.status = std::atoi(raw.c_str() + statusStart + 1);
  size_t line = raw.find("\r\n") + 2;
  while (line < headerEnd) {
    const size_t lineEnd = raw.find("\r\n", line);
    const size_t colon = raw.find(':', line);
    if (colon != std::string::npos && colon < lineEnd) {
      size_t valueStart = colon + 1;
      while (valueStart < lineEnd && raw[valueStart] == ' ') ++valueStart;
      response.headers[raw.substr(line, colon - line)] =
          raw.substr(valueStart, lineEnd - valueStart);
    }
    line = lineEnd + 2;
  }
  response.body = raw.substr(headerEnd + 4);
  return response;
}

FakeHttpResponse httpRequest(PicoWiFiPortal& portal, const std::string& method,
                             const std::string& target,
                             const std::string& body) {
  tcp_pcb* client = fakeTcpConnect(80);
  assert(client != nullptr);
  std::string request = method + " " + target + " HTTP/1.1\r\nHost: portal\r\n";
  if (!body.empty() || method == "POST") {
    request += "Content-Type: application/x-www-form-urlencoded\r\n";
    request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  }
  request += "\r\n" + body;
  assert(fakeTcpSend(client, request) == ERR_OK);
  portal.process();
  FakeHttpResponse response = parseHttpResponse(client->written);
  response.closed = client->state != FakeTcpState::Active;
  return response;
}

// --- CYW43 ------------------------------------------------------------------------

struct netif* fakeStaNetif() { return &cyw43_state.netif[CYW43_ITF_STA]; }
struct netif* fakeApNetif() { return &cyw43_state.netif[CYW43_ITF_AP]; }

PicoWiFiPortal::IPv4Address fakeAddress(const ip4_addr_t* address) {
  return PicoWiFiPortal::IPv4Address::fromUint32(lwip_ntohl(address->addr));
}

bool cyw43_is_initialized(cyw43_t* self) {
  assert(self == &cyw43_state);
  return FakeCyw43.initialized;
}

void cyw43_arch_enable_sta_mode() {
  assert(FakeCyw43.initialized);
  ++FakeCyw43.staEnableCalls;
  FakeCyw43.staEnabled = true;
  cyw43_state.itf_state |= 1u << CYW43_ITF_STA;
}

void cyw43_arch_enable_ap_mode(const char* ssid, const char* password,
                               uint32_t auth) {
  assert(FakeCyw43.initialized);
  ++FakeCyw43.apEnableCalls;
  FakeCyw43.apSSID = ssid ? ssid : "";
  FakeCyw43.apPasswordNull = password == nullptr;
  FakeCyw43.apPassword = password ? password : "";
  FakeCyw43.apAuth = auth;
  if (FakeCyw43.apStartFails) return;
  FakeCyw43.apEnabled = true;
  cyw43_state.itf_state |= 1u << CYW43_ITF_AP;
}

void cyw43_arch_disable_ap_mode() {
  ++FakeCyw43.apDisableCalls;
  FakeCyw43.apEnabled = false;
  cyw43_state.itf_state &= static_cast<uint8_t>(~(1u << CYW43_ITF_AP));
  fakeApNetif()->ip_addr.addr = 0;
  fakeApNetif()->netmask.addr = 0;
  fakeApNetif()->gw.addr = 0;
}

void cyw43_wifi_ap_set_channel(cyw43_t* self, uint32_t channel) {
  assert(self == &cyw43_state);
  FakeCyw43.apChannel = channel;
}

int cyw43_wifi_scan(cyw43_t* self, cyw43_wifi_scan_options_t* opts, void* env,
                    int (*result_cb)(void*, const cyw43_ev_scan_result_t*)) {
  assert(self == &cyw43_state);
  (void)opts;
  ++FakeCyw43.scanCalls;
  if (FakeCyw43.scanResult != 0) return FakeCyw43.scanResult;
  FakeCyw43.scanActive = true;
  FakeCyw43.scanEnv = env;
  FakeCyw43.scanCallback = result_cb;
  return 0;
}

bool cyw43_wifi_scan_active(cyw43_t* self) {
  assert(self == &cyw43_state);
  return FakeCyw43.scanActive;
}

void fakeScanResult(const std::string& ssid, int16_t rssi, uint8_t authMode) {
  assert(FakeCyw43.scanCallback != nullptr);
  cyw43_ev_scan_result_t result = {};
  result.ssid_len = static_cast<uint8_t>(std::min<size_t>(ssid.size(), 255));
  std::memcpy(result.ssid, ssid.data(), std::min<size_t>(ssid.size(), 32));
  result.rssi = rssi;
  result.auth_mode = authMode;
  result.channel = 6;
  LockScope lock;
  FakeCyw43.scanCallback(FakeCyw43.scanEnv, &result);
}

void fakeScanFinish() { FakeCyw43.scanActive = false; }

int cyw43_wifi_get_mac(cyw43_t* self, int itf, uint8_t mac[6]) {
  assert(self == &cyw43_state);
  std::memcpy(mac, itf == CYW43_ITF_AP ? FakeCyw43.apMAC : FakeCyw43.staMAC,
              6);
  return 0;
}

int cyw43_arch_wifi_connect_async(const char* ssid, const char* pw,
                                  uint32_t auth) {
  assert(FakeCyw43.staEnabled);
  ++FakeCyw43.connectCalls;
  FakeCyw43.lastSSID = ssid ? ssid : "";
  FakeCyw43.lastPasswordNull = pw == nullptr;
  FakeCyw43.lastPassword = pw ? pw : "";
  FakeCyw43.lastAuth = auth;
  if (FakeCyw43.connectResult != 0) return FakeCyw43.connectResult;
  FakeCyw43.linkStatus = FakeCyw43.linkStatusAfterConnect;
  return 0;
}

int cyw43_wifi_leave(cyw43_t* self, int itf) {
  assert(self == &cyw43_state);
  assert(itf == CYW43_ITF_STA);
  ++FakeCyw43.leaveCalls;
  if (FakeCyw43.leaveResult == 0) FakeCyw43.linkStatus = CYW43_LINK_DOWN;
  return FakeCyw43.leaveResult;
}

int cyw43_tcpip_link_status(cyw43_t* self, int itf) {
  assert(self == &cyw43_state);
  if (itf != CYW43_ITF_STA) return CYW43_LINK_DOWN;
  if (FakeCyw43.onLinkStatus) FakeCyw43.onLinkStatus();
  return FakeCyw43.linkStatus;
}

void cyw43_arch_poll() {
  ++FakeCyw43.pollCalls;
  if (FakeCyw43.onPoll) FakeCyw43.onPoll();
}

void cyw43_arch_wait_for_work_until(absolute_time_t until) {
  ++FakeCyw43.waitCalls;
  const uint32_t deadline = to_ms_since_boot(until);
  if (static_cast<int32_t>(deadline - FakeMillis) > 0) FakeMillis = deadline;
}

void cyw43_arch_lwip_begin() {
  ++FakeLwip.lockDepth;
  ++FakeLwip.lockCalls;
}

void cyw43_arch_lwip_end() {
  assert(FakeLwip.lockDepth > 0);
  --FakeLwip.lockDepth;
}

void fakeLinkUp(const PicoWiFiPortal::IPv4Address& ip,
                const PicoWiFiPortal::IPv4Address& gateway,
                const PicoWiFiPortal::IPv4Address& subnet) {
  FakeCyw43.linkStatus = CYW43_LINK_UP;
  fakeStaNetif()->ip_addr.addr = lwip_htonl(ip.toUint32());
  fakeStaNetif()->gw.addr = lwip_htonl(gateway.toUint32());
  fakeStaNetif()->netmask.addr = lwip_htonl(subnet.toUint32());
}

// --- Reset ----------------------------------------------------------------------

void resetFakeRuntime(bool preserveFlash) {
  assert(FakeLwip.lockDepth == 0);
  assert(FakeLwip.livePbufs == 0);
  FakeMillis = 0;
  FakeFlash = FakeFlashState();
  FakeCyw43 = FakeCyw43State();
  FakeLwip = FakeLwipState();
  FakeHeapUsed = 131072;
  cyw43_state = cyw43_t();
  if (!preserveFlash) std::memset(pwp_fake_flash, 0xFF, sizeof(pwp_fake_flash));
}

namespace {
// Fresh flash is erased before main() runs.
struct FlashInitializer {
  FlashInitializer() { std::memset(pwp_fake_flash, 0xFF, sizeof(pwp_fake_flash)); }
} flashInitializer;
}  // namespace

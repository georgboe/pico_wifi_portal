#pragma once

// Test-side control of the fake Pico SDK / CYW43 / lwIP runtime declared in
// host/include/fake_sdk.h. All state is global and reset by resetFakeRuntime().

#include <PicoWiFiPortal.h>

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "fake_sdk.h"

// Thrown by watchdog_reboot(). PicoWiFiPortal::process() never returns after
// requesting a reboot, so tests catch this instead.
struct FakeReboot {};

// --- Time -------------------------------------------------------------------

// Milliseconds since boot. Tests set or advance it directly; blocking library
// waits (cyw43_arch_wait_for_work_until) jump it forward to their deadline.
extern uint32_t FakeMillis;

// --- Flash ------------------------------------------------------------------

// The fake program image ends at this flash offset (__flash_binary_end).
constexpr uint32_t kFakeBinaryEndOffset = 0x10000;

struct FakeFlashState {
  uint32_t eraseCalls = 0;
  uint32_t programCalls = 0;
  uint32_t safeExecuteCalls = 0;
  // flash_safe_execute() returns PICO_ERROR_TIMEOUT without running the job
  // while this is > 0 (decremented per call).
  uint32_t failSafeExecute = 0;
  // Simulated power loss: once this many bytes have been erased/programmed
  // (counted across calls) further bytes are left untouched. -1 = unlimited.
  long eraseByteBudget = -1;
  long programByteBudget = -1;
};
extern FakeFlashState FakeFlash;

// Direct access to the fake flash array (PICO_FLASH_SIZE_BYTES bytes).
uint8_t* fakeFlashAt(uint32_t offset);

// --- CYW43 ------------------------------------------------------------------

struct FakeCyw43State {
  bool initialized = true;
  bool staEnabled = false;
  uint32_t staEnableCalls = 0;

  // SoftAP.
  bool apEnabled = false;
  bool apStartFails = false;  // enable_ap_mode leaves itf_state AP bit clear
  uint32_t apEnableCalls = 0;
  uint32_t apDisableCalls = 0;
  std::string apSSID;
  std::string apPassword;  // Empty when the AP was opened without password.
  bool apPasswordNull = true;
  uint32_t apAuth = 0;
  uint32_t apChannel = 0;

  // STA link. cyw43_tcpip_link_status(STA) returns linkStatus.
  int linkStatus = CYW43_LINK_DOWN;
  uint32_t connectCalls = 0;
  int connectResult = 0;
  // linkStatus after a successful cyw43_arch_wifi_connect_async().
  int linkStatusAfterConnect = CYW43_LINK_JOIN;
  std::string lastSSID;
  std::string lastPassword;
  bool lastPasswordNull = true;
  uint32_t lastAuth = 0;
  uint32_t leaveCalls = 0;
  int leaveResult = 0;  // 0 sets linkStatus = DOWN.

  // Scan.
  uint32_t scanCalls = 0;
  int scanResult = 0;
  bool scanActive = false;
  void* scanEnv = nullptr;
  int (*scanCallback)(void*, const cyw43_ev_scan_result_t*) = nullptr;

  uint8_t apMAC[6] = {0x28, 0xCD, 0xC1, 0x00, 0x00, 0x01};
  uint8_t staMAC[6] = {0x28, 0xCD, 0xC1, 0x00, 0x00, 0x02};

  uint32_t pollCalls = 0;
  uint32_t waitCalls = 0;
  // Called from cyw43_arch_poll(); lets a test change link state while the
  // library is inside a blocking loop (connectSaved, startConfigPortal).
  std::function<void()> onPoll;
  // Called at the start of cyw43_tcpip_link_status(STA), before the value is
  // returned, so a test can change the link between two library reads.
  std::function<void()> onLinkStatus;

  uint32_t rebootCalls = 0;
};
extern FakeCyw43State FakeCyw43;

// Delivers one scan result to the active scan callback (under the lwIP lock).
void fakeScanResult(const std::string& ssid, int16_t rssi, uint8_t authMode);
// Marks the scan as finished (cyw43_wifi_scan_active() returns false).
void fakeScanFinish();

// Sets linkStatus = UP and the STA netif address.
void fakeLinkUp(const PicoWiFiPortal::IPv4Address& ip = {192, 168, 1, 50},
                const PicoWiFiPortal::IPv4Address& gateway = {192, 168, 1, 1},
                const PicoWiFiPortal::IPv4Address& subnet = {255, 255, 255, 0});

struct netif* fakeStaNetif();
struct netif* fakeApNetif();
PicoWiFiPortal::IPv4Address fakeAddress(const ip4_addr_t* address);

// --- lwIP -------------------------------------------------------------------

enum FakeUdpState { FakeUdpActive = 1, FakeUdpRemoved = 2 };

enum class FakeTcpState { Active, Listening, Closed, Aborted, Freed };

struct tcp_pcb {
  FakeTcpState state = FakeTcpState::Active;
  const struct netif* boundNetif = nullptr;
  u16_t localPort = 0;
  void* arg = nullptr;
  tcp_accept_fn accept = nullptr;
  tcp_recv_fn recv = nullptr;
  tcp_sent_fn sent = nullptr;
  tcp_err_fn err = nullptr;
  tcp_poll_fn poll = nullptr;
  u8_t pollInterval = 0;
  u16_t sndbuf = 0xFFFF;
  uint32_t recvedBytes = 0;
  uint32_t outputCalls = 0;
  std::string written;  // Everything passed to tcp_write().
};

struct FakeUdpPacket {
  std::vector<uint8_t> data;
  uint32_t address;  // Host byte order.
  u16_t port;
  const struct netif* netif;
};

struct FakeLwipState {
  int lockDepth = 0;
  uint32_t lockCalls = 0;
  int livePbufs = 0;

  std::deque<udp_pcb> udpPcbs;
  std::deque<tcp_pcb> tcpPcbs;
  std::vector<FakeUdpPacket> udpSent;

  // Failure injection.
  bool udpNewFails = false;
  bool tcpNewFails = false;
  bool tcpListenFails = false;
  err_t udpBindResult = ERR_OK;
  // Port whose udp_bind() fails with udpBindResult; 0 = every port.
  u16_t udpBindFailPort = 0;
  err_t tcpBindResult = ERR_OK;
  err_t tcpCloseResult = ERR_OK;
  err_t dhcpStartResult = ERR_OK;
  u16_t defaultSndBuf = 0xFFFF;
  // When set, netif_set_addr() on the AP netif stores this address instead.
  bool apAddressOverride = false;
  uint32_t apAddressOverrideValue = 0;

  struct netif* defaultNetif = nullptr;
  ip_addr_t dnsServers[2] = {};
  uint32_t dhcpStartCalls = 0;
  uint32_t dhcpStopCalls = 0;
};
extern FakeLwipState FakeLwip;

// Finds a live UDP pcb bound to port (nullptr if none).
udp_pcb* fakeUdpPcb(u16_t port);
// Delivers a datagram to the pcb bound to port; returns false if none.
bool fakeUdpDeliver(u16_t port, const std::vector<uint8_t>& data,
                    uint32_t sourceAddress = 0, u16_t sourcePort = 68);

// Finds the listening TCP pcb bound to port (nullptr if none).
tcp_pcb* fakeTcpListener(u16_t port);
// Accepts a new client connection on port; returns the client pcb or nullptr
// if nothing is listening or the server rejected it.
tcp_pcb* fakeTcpConnect(u16_t port = 80);
// Delivers bytes to the server through the recv callback. Returns its err_t.
err_t fakeTcpSend(tcp_pcb* pcb, const std::string& data);
// Remote half-close (recv callback with a null pbuf).
err_t fakeTcpRemoteClose(tcp_pcb* pcb);
// Acknowledges len bytes: restores sndbuf and calls the sent callback.
err_t fakeTcpAck(tcp_pcb* pcb, u16_t len);
// Calls the poll callback.
err_t fakeTcpPoll(tcp_pcb* pcb);

struct FakeHttpResponse {
  int status = 0;
  std::map<std::string, std::string> headers;
  std::string body;
  bool closed = false;  // Server closed or aborted the connection.
};

FakeHttpResponse parseHttpResponse(const std::string& raw);

// Full round trip: connect, send the request, run portal.process() once, and
// parse what the server wrote. A urlencoded body gets a Content-Length header.
FakeHttpResponse httpRequest(PicoWiFiPortal& portal, const std::string& method,
                             const std::string& target,
                             const std::string& body = std::string());

// --- Heap -------------------------------------------------------------------

// mallinfo().uordblks; the fake RAM between __bss_end__ and __StackLimit is
// kFakeHeapTotal bytes, so freeHeap = kFakeHeapTotal - FakeHeapUsed.
constexpr uint32_t kFakeHeapTotal = 262144;
extern size_t FakeHeapUsed;

// --- Reset ------------------------------------------------------------------

// Restores every fake to its defaults. preserveFlash keeps the flash contents
// to simulate a reboot. Asserts that no lwIP lock is held and no pbuf leaked.
void resetFakeRuntime(bool preserveFlash = false);

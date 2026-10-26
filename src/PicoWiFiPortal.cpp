/**
 * @file PicoWiFiPortal.cpp
 * @brief RP2040/RP2350 (Pico W / Pico 2 W) Wi-Fi captive portal for the
 *        Pico SDK. Port of ESP32WiFiPortal 2.1.2 by Tran Nguyen Hien.
 *
 * @copyright Copyright (c) 2026 Tran Nguyen Hien. All rights reserved.
 */

#include "PicoWiFiPortal.h"

#include <malloc.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <new>

#include "PortalNet.h"
#include "PortalPage.h"
#include "hardware/clocks.h"
#include "hardware/watchdog.h"
#include "lwip/dhcp.h"
#include "lwip/dns.h"
#include "lwip/netif.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "pico/unique_id.h"

#if !LWIP_IPV4 || !LWIP_UDP || !LWIP_TCP || !LWIP_DHCP
#error "PicoWiFiPortal requires LWIP_IPV4, LWIP_UDP, LWIP_TCP and LWIP_DHCP in lwipopts.h"
#endif

extern "C" char __StackLimit;
extern "C" char __bss_end__;

using pico_wifi_portal_detail::CredentialStore;
using pico_wifi_portal_detail::HttpMethod;
using pico_wifi_portal_detail::PortalServices;

namespace {
uint32_t nowMs() { return to_ms_since_boot(get_absolute_time()); }

// lwIP raw API calls and buffers shared with lwIP/CYW43 callbacks must be
// guarded. The lock is recursive, so nesting is safe.
class LwipLock {
public:
  LwipLock() { cyw43_arch_lwip_begin(); }
  ~LwipLock() { cyw43_arch_lwip_end(); }
  LwipLock(const LwipLock&) = delete;
  LwipLock& operator=(const LwipLock&) = delete;
};

struct netif* staNetif() { return &cyw43_state.netif[CYW43_ITF_STA]; }
struct netif* apNetif() { return &cyw43_state.netif[CYW43_ITF_AP]; }

ip4_addr_t toLwip(const PicoWiFiPortal::IPv4Address& address) {
  ip4_addr_t result;
  result.addr = lwip_htonl(address.toUint32());
  return result;
}

uint32_t fromLwip(const ip4_addr_t* address) {
  return address ? lwip_ntohl(address->addr) : 0;
}

void appendJsonEscaped(std::string& output, std::string_view value) {
  static const char kHex[] = "0123456789abcdef";
  for (const char raw : value) {
    const uint8_t character = static_cast<uint8_t>(raw);
    switch (character) {
      case '"': output += "\\\""; break;
      case '\\': output += "\\\\"; break;
      case '\b': output += "\\b"; break;
      case '\f': output += "\\f"; break;
      case '\n': output += "\\n"; break;
      case '\r': output += "\\r"; break;
      case '\t': output += "\\t"; break;
      default:
        if (character < 0x20) {
          output += "\\u00";
          output += kHex[character >> 4];
          output += kHex[character & 0x0F];
        } else {
          output += static_cast<char>(character);
        }
        break;
    }
  }
}

void appendIPAddress(std::string& output, uint32_t address) {
  output += PicoWiFiPortal::IPv4Address::fromUint32(address).toString();
}

void appendMACAddress(std::string& output, const uint8_t* address) {
  static const char kHex[] = "0123456789ABCDEF";
  for (uint8_t i = 0; i < 6; ++i) {
    if (i > 0) output += ':';
    output += kHex[address[i] >> 4];
    output += kHex[address[i] & 0x0F];
  }
}

void wipe(std::string& value) {
  CredentialStore::secureClear(value.data(), value.size());
  value.clear();
}

uint32_t freeHeapBytes() {
  const struct mallinfo info = mallinfo();
  const size_t total = static_cast<size_t>(&__StackLimit - &__bss_end__);
  return total > info.uordblks ? static_cast<uint32_t>(total - info.uordblks)
                               : 0;
}

// The CYW43 driver is one process-wide resource. Two portal instances
// installing reconnect policies against it cannot be isolated, so ownership
// is explicit and deterministic instead of allowing races.
PicoWiFiPortal* activeWiFiOwner = nullptr;

// Bumped whenever this library changes the shared flash record. Other
// instances compare it with their cache and reload instead of reusing stale
// credentials.
uint32_t credentialGeneration = 0;
}  // namespace

std::string PicoWiFiPortal::IPv4Address::toString() const {
  char buffer[16];
  snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", _octets[0], _octets[1],
           _octets[2], _octets[3]);
  return buffer;
}

const char* PicoWiFiPortal::portalNetworkValidationMessage(
    PortalNetworkValidationResult result) {
  switch (result) {
    case PortalNetworkValidationResult::InvalidLocalIP:
      return "Portal IP is not a usable unicast IPv4 address";
    case PortalNetworkValidationResult::InvalidGateway:
      return "Portal gateway is not a usable unicast IPv4 address";
    case PortalNetworkValidationResult::InvalidSubnetMask:
      return "Portal subnet mask is invalid or non-contiguous";
    case PortalNetworkValidationResult::UnsupportedSubnet:
      return "Portal subnet must be between /24 and /28 for SoftAP DHCP";
    case PortalNetworkValidationResult::DifferentSubnet:
      return "Portal IP and gateway must be in the same subnet";
    case PortalNetworkValidationResult::LocalIsNetworkAddress:
      return "Portal IP cannot be the subnet network address";
    case PortalNetworkValidationResult::LocalIsBroadcastAddress:
      return "Portal IP cannot be the subnet broadcast address";
    case PortalNetworkValidationResult::GatewayIsNetworkAddress:
      return "Portal gateway cannot be the subnet network address";
    case PortalNetworkValidationResult::GatewayIsBroadcastAddress:
      return "Portal gateway cannot be the subnet broadcast address";
    case PortalNetworkValidationResult::LocalConflictsWithDHCPLease:
      return "Portal IP conflicts with the SoftAP DHCP lease range";
    case PortalNetworkValidationResult::GatewayConflictsWithDHCPLease:
      return "Portal gateway conflicts with the SoftAP DHCP lease range";
    case PortalNetworkValidationResult::Valid:
      return "";
  }
  return "Portal IPv4 configuration is invalid";
}

PicoWiFiPortal::PicoWiFiPortal()
    : _portalIP(192, 168, 4, 1),
      _portalGateway(192, 168, 4, 1),
      _portalSubnet(255, 255, 255, 0) {}

PicoWiFiPortal::~PicoWiFiPortal() {
  stopConfigPortal();
  cancelAutoReconnect(true);
  wipe(_savedPassword);
  if (activeWiFiOwner == this) activeWiFiOwner = nullptr;
}

bool PicoWiFiPortal::ensureWiFiOwner() {
  if (_wifiOwned) return true;
  if (activeWiFiOwner && activeWiFiOwner != this) {
    setError("Wi-Fi is already managed by another PicoWiFiPortal instance");
    return false;
  }
  if (!cyw43_is_initialized(&cyw43_state)) {
    setError("cyw43_arch_init() must be called before using PicoWiFiPortal");
    return false;
  }

  activeWiFiOwner = this;
  // The CYW43 driver has no reconnect policy of its own, so the library is
  // the only reconnect path. STA stays enabled for the object's lifetime.
  cyw43_arch_enable_sta_mode();
#if LWIP_NETIF_HOSTNAME
  if (!_hostname.empty()) {
    LwipLock lock;
    netif_set_hostname(staNetif(), _hostname.c_str());
  }
#endif
  _lastLinkStatus = staLinkStatus();
  _wifiOwned = true;
  return true;
}

bool PicoWiFiPortal::connectSaved(uint32_t timeoutMs) {
  if (!ensureWiFiOwner()) {
    _state = State::Failed;
    return false;
  }
  cancelAutoReconnect(true);
  if (_portalActive) {
    stopConfigPortal();
  }

  if (!ensureCredentialCache()) {
    if (_credentialCacheStatus == CredentialCacheStatus::Unavailable) {
      setError("Credential flash region is unusable; check PICO_WIFI_PORTAL_FLASH_OFFSET");
    } else if (_credentialCacheStatus == CredentialCacheStatus::Corrupt) {
      setError("Saved Wi-Fi credential record is corrupt");
    } else {
      setError("No saved Wi-Fi credentials");
    }
    _state = State::Failed;
    return false;
  }

  const bool connected = connect(timeoutMs);
  if (!connected) scheduleSavedConnectionRecovery();
  return connected;
}

bool PicoWiFiPortal::autoConnect(const char* apSSID,
                                 const char* apPassword,
                                 uint32_t connectTimeoutMs,
                                 uint32_t portalTimeoutMs) {
  if (connectSaved(connectTimeoutMs)) {
    return true;
  }
  return startConfigPortal(apSSID, apPassword, portalTimeoutMs);
}

bool PicoWiFiPortal::startConfigPortal(const char* apSSID,
                                       const char* apPassword,
                                       uint32_t portalTimeoutMs) {
  if (!openPortal(apSSID, apPassword, portalTimeoutMs)) {
    return false;
  }

  while (_portalActive) {
    process();
    waitForWork(2);
  }

  return isConnected();
}

bool PicoWiFiPortal::startConfigPortalAsync(const char* apSSID,
                                            const char* apPassword,
                                            uint32_t portalTimeoutMs) {
  return openPortal(apSSID, apPassword, portalTimeoutMs);
}

bool PicoWiFiPortal::openPortal(const char* apSSID,
                                const char* apPassword,
                                uint32_t portalTimeoutMs) {
  static_assert(pico_wifi_portal_detail::DhcpServer::kLeaseCount ==
                    kDHCPLeaseCount,
                "Portal validation must match the DHCP lease pool");

  if (!apSSID || strlen(apSSID) == 0 || strlen(apSSID) > 32) {
    setError("AP SSID must contain 1-32 bytes");
    return false;
  }
  if (!validAPPassword(apPassword)) {
    setError("AP password must be empty or 8-63 characters");
    return false;
  }

  const uint32_t local = _portalIP.toUint32();
  const uint32_t gateway = _portalGateway.toUint32();
  const uint32_t mask = _portalSubnet.toUint32();
  const PortalNetworkValidationResult validation =
      validatePortalNetwork(local, gateway, mask);
  if (validation != PortalNetworkValidationResult::Valid) {
    setError(portalNetworkValidationMessage(validation));
    return false;
  }

  if (!ensureWiFiOwner()) {
    _state = State::Failed;
    return false;
  }
  // Load the last known-good credentials before a Portal candidate can use
  // the STA interface. They remain cached until a candidate is proven and
  // committed, or the application explicitly erases them.
  ensureCredentialCache();
  stopConfigPortal();
  cancelAutoReconnect(true);
  _lastError.clear();
  _portalSSID = apSSID;
  _portalTimeoutMs = portalTimeoutMs;
  _portalStartedAt = nowMs();
  _connectPending = false;
  releaseSTAConnection();
  _portalRetriesUsed = 0;

  const bool secured = apPassword && apPassword[0] != '\0';
  cyw43_wifi_ap_set_channel(&cyw43_state, _apChannel);
  cyw43_arch_enable_ap_mode(apSSID, secured ? apPassword : nullptr,
                            CYW43_AUTH_WPA2_AES_PSK);
  _apEnabled = true;
  if ((cyw43_state.itf_state & (1u << CYW43_ITF_AP)) == 0) {
    return failPortalStart("Failed to start the CYW43 access point");
  }

  bool addressApplied = false;
  {
    LwipLock lock;
    struct netif* ap = apNetif();
    const ip4_addr_t ip = toLwip(_portalIP);
    const ip4_addr_t netmask = toLwip(_portalSubnet);
    const ip4_addr_t gw = toLwip(_portalGateway);
    netif_set_addr(ap, &ip, &netmask, &gw);
    // CYW43 makes every newly initialised interface the default route. Keep
    // upstream traffic on STA while the portal runs.
    netif_set_default(staNetif());
    // Read back the active netif before DNS and HTTP bind to it.
    addressApplied = fromLwip(netif_ip4_addr(ap)) == local &&
                     fromLwip(netif_ip4_netmask(ap)) == mask;
  }
  if (!addressApplied) {
    return failPortalStart(
        "SoftAP runtime IP/subnet does not match the portal configuration");
  }

  _redirectURL = "http://" + _portalIP.toString() + "/";

  _services.reset(new (std::nothrow) PortalServices);
  if (!_services) {
    return failPortalStart("Unable to allocate captive portal services");
  }

  const char* serviceError = nullptr;
  {
    LwipLock lock;
    if (!_services->dhcp.start(apNetif(), local, gateway, mask,
                               defaultDHCPLeaseStart(local, mask))) {
      serviceError = "Failed to start captive portal DHCP";
    } else if (!_services->dns.start(apNetif(), kDnsPort, local)) {
      serviceError = "Failed to start captive portal DNS";
    } else if (!_services->http.start(apNetif(), kHttpPort)) {
      serviceError = "Failed to start captive portal HTTP server";
    }
  }
  if (serviceError) {
    return failPortalStart(serviceError);
  }

  _portalActive = true;
  _state = State::Portal;
  logf("[PWP] Portal started: http://%s\n", _portalIP.toString().c_str());
  invoke(_onPortalStarted);
  return true;
}

bool PicoWiFiPortal::failPortalStart(const char* message) {
  _portalActive = false;
  clearPendingConnection(true);
  shutdownPortal();
  setError(message);
  _state = isConnected() ? State::Connected : State::Failed;
  scheduleSavedConnectionRecovery();
  return false;
}

void PicoWiFiPortal::shutdownPortal() {
  if (_services) {
    LwipLock lock;
    _services.reset();
  }
  resetScan();
  if (_apEnabled) {
    cyw43_arch_disable_ap_mode();
    _apEnabled = false;
    LwipLock lock;
    netif_set_default(staNetif());
  }

  _portalTimeoutMs = 0;
  _portalStartedAt = 0;
  _responseBuffer = std::string();
  _redirectURL = std::string();
}

void PicoWiFiPortal::dispatchRequest(void* context, HttpRequest& request) {
  static_cast<PicoWiFiPortal*>(context)->handleRequest(request);
}

void PicoWiFiPortal::handleRequest(HttpRequest& request) {
  const std::string_view path = request.path();
  const HttpMethod method = request.method();

  if (method == HttpMethod::Get && (path == "/" || path == "/wifi")) {
    handleRoot(request);
  } else if (method == HttpMethod::Get && path == "/scan") {
    handleScan(request);
  } else if (method == HttpMethod::Post && path == "/save") {
    handleSave(request);
  } else if (method == HttpMethod::Get && path == "/status") {
    handleStatus(request);
  } else if (method == HttpMethod::Get && path == "/properties") {
    handleProperties(request);
  } else if (method == HttpMethod::Post && path == "/reset") {
    handleReset(request);
  } else {
    // Captive portal probes used by Android, Apple and Windows
    // (/generate_204, /hotspot-detect.html, /connecttest.txt, ...) and every
    // unknown URL redirect to the portal.
    handleCaptiveProbe(request);
  }
}

void PicoWiFiPortal::handleRoot(HttpRequest& request) {
  request.sendStatic(200, "text/html; charset=utf-8", PWP_PORTAL_HTML);
}

int PicoWiFiPortal::onScanResult(void* env,
                                 const cyw43_ev_scan_result_t* result) {
  // Runs in the CYW43 async context: fixed storage only, no heap.
  PicoWiFiPortal* self = static_cast<PicoWiFiPortal*>(env);
  if (!self || !self->_scanAccepting || !result || result->ssid_len == 0 ||
      result->ssid_len > 32) {
    return 0;
  }

  const size_t length = result->ssid_len;
  const bool open = result->auth_mode == 0;
  for (size_t i = 0; i < self->_scanResultCount; ++i) {
    ScanResult& existing = self->_scanResults[i];
    if (strlen(existing.ssid) == length &&
        memcmp(existing.ssid, result->ssid, length) == 0) {
      // Emit unique SSIDs only, keeping the strongest access point.
      if (result->rssi > existing.rssi) {
        existing.rssi = result->rssi;
        existing.open = open;
      }
      return 0;
    }
  }

  size_t slot = self->_scanResultCount;
  if (slot >= kMaxScanResults) {
    // Keep the strongest networks when the table is full.
    slot = 0;
    for (size_t i = 1; i < kMaxScanResults; ++i) {
      if (self->_scanResults[i].rssi < self->_scanResults[slot].rssi) slot = i;
    }
    if (self->_scanResults[slot].rssi >= result->rssi) return 0;
  } else {
    ++self->_scanResultCount;
  }

  ScanResult& entry = self->_scanResults[slot];
  memcpy(entry.ssid, result->ssid, length);
  entry.ssid[length] = '\0';
  entry.rssi = result->rssi;
  entry.open = open;
  return 0;
}

bool PicoWiFiPortal::startScan() {
  LwipLock lock;
  _scanResultCount = 0;
  _scanStartedAt = nowMs();
  _scanAccepting = true;
  cyw43_wifi_scan_options_t options = {};
  if (cyw43_wifi_scan(&cyw43_state, &options, this,
                      &PicoWiFiPortal::onScanResult) != 0) {
    _scanAccepting = false;
    _scanState = ScanState::Failed;
    return false;
  }
  _scanState = ScanState::Scanning;
  return true;
}

void PicoWiFiPortal::processScan() {
  // Only the CYW43 callback runs concurrently, and it never changes the
  // state, so this check needs no lock.
  if (_scanState != ScanState::Scanning) return;
  LwipLock lock;

  if (!cyw43_wifi_scan_active(&cyw43_state)) {
    _scanAccepting = false;
    _scanState = ScanState::Ready;
    return;
  }
  if (nowMs() - _scanStartedAt < kScanTimeoutMs) return;

  // CYW43 has no scan abort. This explicit upper bound prevents an unusual
  // driver state from leaving the Portal stuck polling; late results are
  // ignored.
  _scanAccepting = false;
  _scanResultCount = 0;
  _scanState = ScanState::Failed;
}

void PicoWiFiPortal::resetScan() {
  // Idle always implies the scan callback is not accepting results.
  if (_scanState == ScanState::Idle) return;
  LwipLock lock;
  _scanAccepting = false;
  _scanState = ScanState::Idle;
  _scanStartedAt = 0;
  _scanResultCount = 0;
}

void PicoWiFiPortal::handleScan(HttpRequest& request) {
  if (_connectPending || _connectAttemptActive) {
    request.sendHeader("Cache-Control", "no-store");
    request.send(409, "application/json; charset=utf-8",
                 "{\"networks\":[],\"error\":\"Wi-Fi connection in progress\"}");
    return;
  }

  processScan();
  if (_scanState == ScanState::Idle) startScan();

  if (_scanState == ScanState::Scanning) {
    request.sendHeader("Cache-Control", "no-store");
    request.sendHeader("Retry-After", "1");
    request.send(202, "application/json; charset=utf-8", "{\"scanning\":true}");
    return;
  }

  if (_scanState == ScanState::Failed) {
    request.sendHeader("Cache-Control", "no-store");
    request.send(503, "application/json; charset=utf-8",
                 "{\"networks\":[],\"error\":\"Wi-Fi scan failed\"}");
    resetScan();
    return;
  }

  // Strongest first. The table is small, so an index insertion sort is fine.
  uint8_t order[kMaxScanResults];
  const size_t count = _scanResultCount;
  for (size_t i = 0; i < count; ++i) {
    size_t j = i;
    while (j > 0 && _scanResults[order[j - 1]].rssi < _scanResults[i].rssi) {
      order[j] = order[j - 1];
      --j;
    }
    order[j] = static_cast<uint8_t>(i);
  }

  _responseBuffer.clear();
  _responseBuffer.reserve(96 + count * 80);
  _responseBuffer = "{\"networks\":[";
  for (size_t i = 0; i < count; ++i) {
    const ScanResult& network = _scanResults[order[i]];
    if (i > 0) _responseBuffer += ',';
    _responseBuffer += "{\"ssid\":\"";
    appendJsonEscaped(_responseBuffer, network.ssid);
    _responseBuffer += "\",\"rssi\":";
    _responseBuffer += std::to_string(network.rssi);
    _responseBuffer += ",\"open\":";
    _responseBuffer += network.open ? "true" : "false";
    _responseBuffer += '}';
  }
  _responseBuffer += "]}";
  resetScan();

  request.sendHeader("Cache-Control", "no-store");
  request.send(200, "application/json; charset=utf-8", _responseBuffer);
}

void PicoWiFiPortal::handleSave(HttpRequest& request) {
  if (_connectPending || _connectAttemptActive) {
    request.send(409, "text/plain; charset=utf-8",
                 "A Wi-Fi connection attempt is already running");
    return;
  }

  _pendingSSID = request.arg("ssid");
  _pendingPassword = request.arg("password");

  if (!CredentialStore::validCredentials(_pendingSSID, _pendingPassword)) {
    wipe(_pendingSSID);
    wipe(_pendingPassword);
    request.send(400, "text/plain; charset=utf-8",
                 "SSID must be 1-32 bytes; password must be empty, 8-63 bytes, or a 64-digit hexadecimal PSK");
    return;
  }

  // A valid connection request takes priority over a scan started by another
  // Portal client. The normal UI only submits after scan results are ready.
  resetScan();

  _connectPending = true;
  _connectPendingAt = nowMs();
  _connectPendingDelayMs = 350;
  _portalRetriesUsed = 0;
  _attemptTerminalFailure = false;
  _lastError.clear();

  request.sendStatic(200, "text/html; charset=utf-8", PWP_CONNECTING_HTML);
}

void PicoWiFiPortal::handleStatus(HttpRequest& request) {
  const bool candidateInProgress =
      _connectPending ||
      (_connectAttemptActive && _connectionOwner == ConnectionOwner::Portal);
  const bool connected = isConnected();
  _responseBuffer.clear();
  _responseBuffer.reserve(96 + _lastError.length());
  _responseBuffer = "{\"connected\":";
  _responseBuffer += connected && !candidateInProgress ? "true" : "false";
  _responseBuffer += ",\"portal\":";
  _responseBuffer += isPortalActive() ? "true" : "false";
  _responseBuffer += ",\"ip\":\"";
  appendIPAddress(_responseBuffer, connected ? localIP().toUint32()
                                             : fromLwip(netif_ip4_addr(apNetif())));
  _responseBuffer += "\",\"error\":\"";
  appendJsonEscaped(_responseBuffer, _lastError);
  _responseBuffer += "\"}";
  request.sendHeader("Cache-Control", "no-store");
  request.send(200, "application/json; charset=utf-8", _responseBuffer);
}

void PicoWiFiPortal::handleProperties(HttpRequest& request) {
  const bool staConnected = isConnected();
  uint8_t apMAC[6] = {};
  uint8_t staMAC[6] = {};
  cyw43_wifi_get_mac(&cyw43_state, CYW43_ITF_AP, apMAC);
  cyw43_wifi_get_mac(&cyw43_state, CYW43_ITF_STA, staMAC);
  char chipId[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
  pico_get_unique_board_id_string(chipId, sizeof(chipId));

  struct netif* ap = apNetif();
  struct netif* sta = staNetif();

  _responseBuffer.clear();
  _responseBuffer.reserve(480 + _portalSSID.length());
  _responseBuffer = "{\"ssid\":\"";
  appendJsonEscaped(_responseBuffer, _portalSSID);
  _responseBuffer += "\",\"softap\":{\"ip\":\"";
  appendIPAddress(_responseBuffer, fromLwip(netif_ip4_addr(ap)));
  _responseBuffer += "\",\"gateway\":\"";
  appendIPAddress(_responseBuffer, _portalGateway.toUint32());
  _responseBuffer += "\",\"subnet\":\"";
  appendIPAddress(_responseBuffer, fromLwip(netif_ip4_netmask(ap)));
  _responseBuffer += "\"},\"sta\":{\"connected\":";
  _responseBuffer += staConnected ? "true" : "false";
  _responseBuffer += ",\"ip\":\"";
  if (staConnected) appendIPAddress(_responseBuffer, fromLwip(netif_ip4_addr(sta)));
  _responseBuffer += "\",\"gateway\":\"";
  if (staConnected) appendIPAddress(_responseBuffer, fromLwip(netif_ip4_gw(sta)));
  _responseBuffer += "\",\"subnet\":\"";
  if (staConnected) appendIPAddress(_responseBuffer, fromLwip(netif_ip4_netmask(sta)));
  _responseBuffer += "\"},\"mac\":{\"ap\":\"";
  appendMACAddress(_responseBuffer, apMAC);
  _responseBuffer += "\",\"sta\":\"";
  appendMACAddress(_responseBuffer, staMAC);
  _responseBuffer += "\"},\"chipId\":\"";
  _responseBuffer += chipId;
#if PICO_RP2350
  _responseBuffer += "\",\"chip\":\"RP2350";
#else
  _responseBuffer += "\",\"chip\":\"RP2040";
#endif
  _responseBuffer += "\",\"cpuMHz\":";
  _responseBuffer += std::to_string(clock_get_hz(clk_sys) / 1000000UL);
  _responseBuffer += ",\"flashSize\":";
  _responseBuffer += std::to_string(PICO_FLASH_SIZE_BYTES);
  _responseBuffer += ",\"freeHeap\":";
  _responseBuffer += std::to_string(freeHeapBytes());
  _responseBuffer += '}';

  request.sendHeader("Cache-Control", "no-store");
  request.send(200, "application/json; charset=utf-8", _responseBuffer);
}

void PicoWiFiPortal::handleReset(HttpRequest& request) {
  request.sendHeader("Cache-Control", "no-store");
  request.send(202, "application/json; charset=utf-8", "{\"restarting\":true}");

  // Keep the first timestamp so repeated POSTs cannot postpone the reboot.
  if (!_restartPending) {
    _restartRequestedAt = nowMs();
    _restartPending = true;
  }
}

void PicoWiFiPortal::handleCaptiveProbe(HttpRequest& request) {
  request.sendHeader("Location", _redirectURL);
  request.send(302, "text/plain", "");
}

void PicoWiFiPortal::process() {
  if (!_wifiOwned) return;
  cyw43_arch_poll();
  processWiFiEvents();

  if (_restartPending &&
      nowMs() - _restartRequestedAt >= kRestartDelayMs) {
    _restartPending = false;
    watchdog_reboot(0, 0, 0);
    while (true) tight_loop_contents();
  }

  if (_portalActive) {
    processScan();
    if (_services) {
      LwipLock lock;
      _services->http.poll(&PicoWiFiPortal::dispatchRequest, this);
    }

    if (portalTimedOut()) {
      setError("Configuration portal timed out");
      log("[PWP] Portal timeout");
      stopConfigPortal();
      if (isConnected()) {
        _state = State::Connected;
      } else if (_reconnectScheduled ||
                 (_connectAttemptActive &&
                  _connectionOwner == ConnectionOwner::Reconnect)) {
        _state = State::Connecting;
      } else {
        _state = State::Failed;
      }
      return;
    }

    if (_connectPending && !_connectAttemptActive &&
        nowMs() - _connectPendingAt >= _connectPendingDelayMs) {
      beginPendingConnection();
      return;
    }

    if (_connectAttemptActive && _connectionOwner == ConnectionOwner::Portal) {
      if (!advanceSTAConnection()) {
        clearPendingConnection(false);
        _state = State::Portal;
        return;
      }

      if (_connectionPhase != ConnectionPhase::Connecting) return;

      if (isConnected()) {
        _lastLinkStatus = CYW43_LINK_UP;
        if (!saveCredentials(_pendingSSID, _pendingPassword)) {
          clearPendingConnection(true);
          _state = State::Portal;
          setError("Connected, but unable to save Wi-Fi settings");
          return;
        }
        clearPendingConnection(false);
        _state = State::Connected;
        invoke(_onCredentialsSaved);
        invoke(_onConnected);
        stopConfigPortal();
        _state = State::Connected;
        return;
      }

      if (_attemptTerminalFailure) {
        failPendingConnection(true);
      } else if (_attemptEnded ||
                 nowMs() - _connectAttemptAt >= _connectTimeoutMs) {
        failPendingConnection(false);
      }
    }
  }

  processAutoReconnect();
}

void PicoWiFiPortal::beginPendingConnection() {
  if (!_connectPending || _connectAttemptActive) return;

  _connectPending = false;
  _lastError.clear();
  if (!beginSTAConnection(ConnectionOwner::Portal)) {
    clearPendingConnection(false);
    _state = State::Portal;
  }
}

void PicoWiFiPortal::clearPendingConnection(bool disconnectSTA) {
  const bool ownsSTA = _connectionOwner == ConnectionOwner::Portal;
  if (disconnectSTA && ownsSTA && _connectAttemptActive) {
    cancelSTAConnection();
  } else if (ownsSTA) {
    releaseSTAConnection();
    _staDisconnected = !isConnected();
  }

  _connectPending = false;
  _connectPendingAt = 0;
  _connectPendingDelayMs = 350;
  _portalRetriesUsed = 0;
  wipe(_pendingSSID);
  wipe(_pendingPassword);
}

void PicoWiFiPortal::failPendingConnection(bool terminalFailure) {
  cancelSTAConnection();

  if (!terminalFailure && _portalRetriesUsed < _maxConnectionRetries) {
    ++_portalRetriesUsed;
    _connectPending = true;
    _connectPendingAt = nowMs();
    _connectPendingDelayMs = retryDelay(_portalRetriesUsed);
    _state = State::Portal;
    _lastError.clear();
    logf("[PWP] Retry %u/%u\n", _portalRetriesUsed, _maxConnectionRetries);
    return;
  }

  clearPendingConnection(false);
  _state = State::Portal;
  setError(terminalFailure
               ? "Wi-Fi authentication failed. Check the password and try again."
               : "Unable to connect. Check the SSID/password and try again.");
}

bool PicoWiFiPortal::beginSTAConnection(ConnectionOwner owner) {
  if (_connectAttemptActive || owner == ConnectionOwner::None) {
    setError("A Wi-Fi connection attempt is already running");
    return false;
  }

  if (!ensureWiFiOwner()) return false;

  processWiFiEvents();

  _connectionOwner = owner;
  _connectionPhase = ConnectionPhase::Settling;
  _connectAttemptActive = true;
  _connectAttemptAt = 0;
  _connectionPhaseAt = nowMs();
  _connectionSettleDelayMs = 0;
  _attemptTerminalFailure = false;
  _attemptEnded = false;

  // cancelSTAConnection() already leaves STA clean. Avoid a second disconnect
  // before the next retry, but remain conservative for the first attempt or a
  // currently connected interface.
  if (!_staDisconnected || isConnected()) {
    const bool wasConnected = isConnected();
    if (leaveSTA() != 0 && wasConnected && isConnected()) {
      releaseSTAConnection();
      setError("Failed to disconnect the current STA connection");
      return false;
    }
    _staDisconnected = true;
    _connectionSettleDelayMs = kSTADisconnectSettleMs;
  }
  return true;
}

bool PicoWiFiPortal::advanceSTAConnection() {
  if (!_connectAttemptActive) return false;
  if (_connectionPhase == ConnectionPhase::Connecting) return true;
  if (_connectionPhase != ConnectionPhase::Settling) return false;
  if (nowMs() - _connectionPhaseAt < _connectionSettleDelayMs) return true;

  if (!applySTAConfig()) {
    cancelSTAConnection();
    setError("Failed to apply STA IP/DNS configuration");
    return false;
  }

  const std::string* ssid = nullptr;
  const std::string* password = nullptr;
  if (_connectionOwner == ConnectionOwner::Portal) {
    ssid = &_pendingSSID;
    password = &_pendingPassword;
  } else if (_connectionOwner == ConnectionOwner::Blocking ||
             _connectionOwner == ConnectionOwner::Reconnect) {
    // The credentials may have been erased or replaced while settling.
    if (!ensureCredentialCache()) {
      cancelSTAConnection();
      setError("Wi-Fi credentials are unavailable");
      return false;
    }
    ssid = &_savedSSID;
    password = &_savedPassword;
  }
  if (!ssid || ssid->empty() || !password) {
    cancelSTAConnection();
    setError("Wi-Fi credentials are unavailable");
    return false;
  }

  _connectionPhase = ConnectionPhase::Connecting;
  _connectAttemptAt = nowMs();
  _attemptTerminalFailure = false;
  _attemptEnded = false;
  log("[PWP] Connect");

  _staDisconnected = false;
  _expectingLocalDisconnect = false;
  const int result = cyw43_arch_wifi_connect_async(
      ssid->c_str(), password->empty() ? nullptr : password->c_str(),
      CYW43_AUTH_WPA2_AES_PSK);
  if (result != 0) {
    cancelSTAConnection();
    setError("Unable to start Wi-Fi connection");
    return false;
  }
  // cyw43_wifi_join() marks the join active synchronously. Resetting the
  // observed state guarantees that an immediate repeat failure is still seen
  // as a transition.
  _lastLinkStatus = CYW43_LINK_JOIN;
  return true;
}

bool PicoWiFiPortal::applySTAConfig() {
  LwipLock lock;
  struct netif* sta = staNetif();
  if (_staStaticIPEnabled) {
    dhcp_release_and_stop(sta);
    const ip4_addr_t ip = toLwip(_staIP);
    const ip4_addr_t netmask = toLwip(_staSubnet);
    const ip4_addr_t gateway = toLwip(_staGateway);
    netif_set_addr(sta, &ip, &netmask, &gateway);
#if LWIP_DNS
    if (_staPrimaryDNS.toUint32() != 0) {
      ip_addr_t primary;
      ip_addr_copy_from_ip4(primary, toLwip(_staPrimaryDNS));
      dns_setserver(0, &primary);
    }
    if (_staSecondaryDNS.toUint32() != 0) {
      ip_addr_t secondary;
      ip_addr_copy_from_ip4(secondary, toLwip(_staSecondaryDNS));
      dns_setserver(1, &secondary);
    }
#endif
    return true;
  }

  // Clearing the address and restarting DHCP before every managed attempt
  // also cleanly exits a previous static configuration.
  const ip4_addr_t zero = {0};
  netif_set_addr(sta, &zero, &zero, &zero);
  return dhcp_start(sta) == ERR_OK;
}

void PicoWiFiPortal::releaseSTAConnection() {
  _connectAttemptActive = false;
  _connectionOwner = ConnectionOwner::None;
  _connectionPhase = ConnectionPhase::Idle;
  _connectAttemptAt = 0;
  _connectionPhaseAt = 0;
  _connectionSettleDelayMs = 0;
  _attemptTerminalFailure = false;
  _attemptEnded = false;
}

void PicoWiFiPortal::cancelSTAConnection() {
  const bool disconnectSTA =
      _connectAttemptActive &&
      _connectionPhase == ConnectionPhase::Connecting &&
      !_staDisconnected;
  releaseSTAConnection();
  if (disconnectSTA) {
    const bool left = leaveSTA() == 0;
    _staDisconnected = left || !isConnected();
    if (!_staDisconnected) {
      setError("Failed to cancel the STA connection attempt");
    }
  }
}

int PicoWiFiPortal::leaveSTA() {
  // The link-down that follows our own disassociation is reported like
  // ASSOC_LEAVE on ESP32 and must not trigger Auto Reconnect.
  const int status = staLinkStatus();
  if (status == CYW43_LINK_NOIP || status == CYW43_LINK_UP) {
    _expectingLocalDisconnect = true;
  }
  return cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
}

int PicoWiFiPortal::staLinkStatus() const {
  return cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
}

void PicoWiFiPortal::processWiFiEvents() {
  if (!_wifiOwned) return;

  // CYW43 has no event callback API, so derive ESP32-style STA events from
  // link status transitions.
  const int status = staLinkStatus();
  const int previous = _lastLinkStatus;
  if (status == previous) return;
  _lastLinkStatus = status;

  const bool associatedNow =
      status == CYW43_LINK_NOIP || status == CYW43_LINK_UP;
  const bool wasAssociated =
      previous == CYW43_LINK_NOIP || previous == CYW43_LINK_UP;
  const bool connectedNow = status == CYW43_LINK_UP;

  if (associatedNow && !wasAssociated) {
    log("[PWP] STA connected");
    _staDisconnected = false;
  }

  if (connectedNow) {
    _staDisconnected = false;
    logf("[PWP] Got IP: %s\n", localIP().toString().c_str());
    if (_connectionOwner == ConnectionOwner::None && !_portalActive) {
      _reconnectScheduled = false;
      _reconnectRetriesUsed = 0;
      _state = State::Connected;
    }
    return;
  }

  DisconnectReason reason = DisconnectReason::None;
  if (status == CYW43_LINK_BADAUTH) {
    reason = DisconnectReason::AuthFailed;
  } else if (status == CYW43_LINK_NONET) {
    reason = DisconnectReason::NetworkNotFound;
  } else if (status == CYW43_LINK_FAIL) {
    reason = DisconnectReason::JoinFailed;
  } else if (wasAssociated && !associatedNow) {
    reason = DisconnectReason::LinkLost;
  }
  if (reason == DisconnectReason::None) return;

  const bool localLeave =
      reason == DisconnectReason::LinkLost && _expectingLocalDisconnect;
  if (!associatedNow) _expectingLocalDisconnect = false;
  if (localLeave) reason = DisconnectReason::LeftByRequest;

  _lastDisconnectReason = reason;
  logDisconnect(reason);
  if (!_connectAttemptActive) _staDisconnected = true;
  if (localLeave) return;

  if (_connectAttemptActive) {
    if (_connectionPhase == ConnectionPhase::Connecting) {
      // Saved credentials may see an authentication failure during weak
      // signal, AP overload, or a router restart. Only an unproven
      // Portal/initial blocking candidate treats it as terminal. Reconnect
      // always remains recoverable through its bounded cooldown policy.
      if (reason == DisconnectReason::AuthFailed &&
          _connectionOwner != ConnectionOwner::Reconnect) {
        _attemptTerminalFailure = true;
      } else {
        // The driver does not retry a failed join; end this attempt now
        // instead of waiting for the connect timeout.
        _attemptEnded = true;
      }
    }
    return;
  }

  if (_autoReconnectEnabled && !_portalActive && _state == State::Connected) {
    _reconnectRetriesUsed = 0;
    scheduleAutoReconnect(_retryIntervalMs);
  }
}

void PicoWiFiPortal::processAutoReconnect() {
  if (!_autoReconnectEnabled || _portalActive) return;

  if (_connectAttemptActive && _connectionOwner == ConnectionOwner::Reconnect) {
    if (!advanceSTAConnection()) {
      scheduleNextAutoReconnect();
      return;
    }
    if (_connectionPhase != ConnectionPhase::Connecting) return;

    if (isConnected()) {
      // isConnected() is the success check here, so record UP. Otherwise a
      // later drop would look like a transition from JOIN and not LinkLost.
      _lastLinkStatus = CYW43_LINK_UP;
      releaseSTAConnection();
      _staDisconnected = false;
      _reconnectScheduled = false;
      _reconnectRetriesUsed = 0;
      _lastError.clear();
      _state = State::Connected;
      invoke(_onConnected);
      return;
    }

    if (!_attemptEnded && nowMs() - _connectAttemptAt < _connectTimeoutMs) {
      return;
    }

    cancelSTAConnection();
    scheduleNextAutoReconnect();
    return;
  }

  if (!_reconnectScheduled || _connectAttemptActive ||
      nowMs() - _reconnectScheduledAt < _reconnectDelayMs) {
    return;
  }

  if (isConnected()) {
    _lastLinkStatus = CYW43_LINK_UP;
    _reconnectScheduled = false;
    _reconnectRetriesUsed = 0;
    _staDisconnected = false;
    _state = State::Connected;
    return;
  }

  if (!ensureCredentialCache()) {
    _reconnectScheduled = false;
    setError(_credentialCacheStatus == CredentialCacheStatus::NotFound
                 ? "Auto reconnect requires saved Wi-Fi credentials"
                 : "Auto reconnect rejected an unusable credential record");
    _state = State::Failed;
    return;
  }

  _reconnectScheduled = false;
  if (_reconnectRetriesUsed == 0) {
    log("[PWP] Reconnect");
  } else {
    logf("[PWP] Retry %u/%u\n", _reconnectRetriesUsed, _maxConnectionRetries);
  }

  _state = State::Connecting;
  if (!beginSTAConnection(ConnectionOwner::Reconnect)) {
    scheduleNextAutoReconnect();
  }
}

void PicoWiFiPortal::scheduleAutoReconnect(uint32_t delayMs) {
  if (!_autoReconnectEnabled || _portalActive) return;
  _reconnectScheduled = true;
  _reconnectScheduledAt = nowMs();
  _reconnectDelayMs = delayMs;
  _state = State::Connecting;
}

void PicoWiFiPortal::scheduleNextAutoReconnect() {
  if (_reconnectRetriesUsed < _maxConnectionRetries) {
    ++_reconnectRetriesUsed;
    scheduleAutoReconnect(retryDelay(_reconnectRetriesUsed));
    return;
  }

  _reconnectRetriesUsed = 0;
  scheduleAutoReconnect(_maxRetryIntervalMs);
  log("[PWP] Reconnect cooldown");
}

bool PicoWiFiPortal::scheduleSavedConnectionRecovery() {
  if (!_autoReconnectEnabled || _portalActive || _connectAttemptActive ||
      isConnected()) {
    return false;
  }
  if (!ensureCredentialCache()) return false;

  _reconnectRetriesUsed = 0;
  scheduleAutoReconnect(_retryIntervalMs);
  log("[PWP] Restoring saved Wi-Fi");
  return true;
}

void PicoWiFiPortal::cancelAutoReconnect(bool disconnectSTA) {
  _reconnectScheduled = false;
  _reconnectRetriesUsed = 0;
  _reconnectScheduledAt = 0;
  _reconnectDelayMs = 0;
  if (_connectionOwner == ConnectionOwner::Reconnect) {
    if (disconnectSTA) {
      cancelSTAConnection();
    } else {
      releaseSTAConnection();
      _staDisconnected = !isConnected();
    }
  }
}

uint32_t PicoWiFiPortal::retryDelay(uint8_t retryNumber) const {
  uint32_t delayMs = _retryIntervalMs;
  for (uint8_t i = 1; i < retryNumber && delayMs < _maxRetryIntervalMs; ++i) {
    if (delayMs > _maxRetryIntervalMs / 2) {
      delayMs = _maxRetryIntervalMs;
    } else {
      delayMs *= 2;
    }
  }
  return delayMs > _maxRetryIntervalMs ? _maxRetryIntervalMs : delayMs;
}

bool PicoWiFiPortal::connect(uint32_t timeoutMs) {
  if (_savedSSID.empty()) {
    setError("SSID cannot be empty");
    _state = State::Failed;
    return false;
  }

  if (_portalActive) {
    stopConfigPortal();
  }

  if (!ensureWiFiOwner()) {
    _state = State::Failed;
    return false;
  }
  cancelAutoReconnect(true);
  if (timeoutMs == 0) {
    timeoutMs = kDefaultConnectTimeoutMs;
    log("[PWP] Connect timeout 0 normalized to 15000 ms");
  }
  _state = State::Connecting;
  _lastError.clear();
  uint8_t retriesUsed = 0;

  while (true) {
    if (!beginSTAConnection(ConnectionOwner::Blocking)) {
      _state = State::Failed;
      return false;
    }

    bool setupFailed = false;
    while (true) {
      processWiFiEvents();
      if (!advanceSTAConnection()) {
        setupFailed = true;
        break;
      }
      if (_connectionPhase != ConnectionPhase::Connecting) {
        waitForWork(1);
        continue;
      }
      if (isConnected()) break;
      if (_attemptTerminalFailure || _attemptEnded ||
          nowMs() - _connectAttemptAt >= timeoutMs) {
        break;
      }
      waitForWork(10);
    }

    if (setupFailed) {
      _state = State::Failed;
      return false;
    }

    if (isConnected()) {
      _lastLinkStatus = CYW43_LINK_UP;
      releaseSTAConnection();
      _staDisconnected = false;
      _state = State::Connected;
      invoke(_onConnected);
      return true;
    }

    // An attempt ended early by NONET/FAIL is not a timeout. Read the state
    // before cancelSTAConnection() clears it.
    const bool terminalFailure = _attemptTerminalFailure;
    const bool attemptEnded = _attemptEnded;
    const DisconnectReason reason = _lastDisconnectReason;
    cancelSTAConnection();
    if (terminalFailure || retriesUsed >= _maxConnectionRetries) {
      const char* message = "Wi-Fi connection timed out";
      if (terminalFailure) {
        message = "Wi-Fi authentication failed";
      } else if (attemptEnded && reason == DisconnectReason::NetworkNotFound) {
        message = "Wi-Fi network not found";
      } else if (attemptEnded && reason == DisconnectReason::JoinFailed) {
        message = "Wi-Fi join failed";
      }
      setError(message);
      _state = State::Failed;
      return false;
    }

    ++retriesUsed;
    const uint32_t waitMs = retryDelay(retriesUsed);
    logf("[PWP] Retry %u/%u\n", retriesUsed, _maxConnectionRetries);
    const uint32_t waitStartedAt = nowMs();
    while (nowMs() - waitStartedAt < waitMs) {
      processWiFiEvents();
      waitForWork(5);
    }
  }
}

void PicoWiFiPortal::stopConfigPortal() {
  const bool wasPortalActive = _portalActive;
  _portalActive = false;
  clearPendingConnection(true);
  shutdownPortal();
  if (wasPortalActive) log("[PWP] Portal stopped");

  if (_state == State::Portal) {
    _state = isConnected() ? State::Connected : State::Idle;
  }

  if (wasPortalActive && !isConnected()) {
    scheduleSavedConnectionRecovery();
  }
}

bool PicoWiFiPortal::saveCredentials(const std::string& ssid,
                                     const std::string& password) {
  if (!CredentialStore::validCredentials(ssid, password)) {
    setError("Invalid Wi-Fi credentials");
    return false;
  }

  // A failed save may still have touched flash, so invalidate other caches
  // either way.
  ++credentialGeneration;
  if (!_credentialStore.save(ssid, password)) {
    setError("Unable to commit the Wi-Fi credential transaction");
    return false;
  }

  _savedSSID = ssid;
  _savedPassword = password;
  _credentialCacheStatus = CredentialCacheStatus::Valid;
  _credentialGeneration = credentialGeneration;
  return true;
}

bool PicoWiFiPortal::ensureCredentialCache() {
  // Another instance changed the shared record since this cache was filled.
  if (_credentialGeneration != credentialGeneration) {
    clearCredentialCache(CredentialCacheStatus::Unknown);
  }
  if (_credentialCacheStatus == CredentialCacheStatus::Valid) return true;
  if (_credentialCacheStatus != CredentialCacheStatus::Unknown) return false;

  std::string ssid;
  std::string password;
  switch (_credentialStore.load(ssid, password)) {
    case CredentialStore::Status::Valid:
      _savedSSID = std::move(ssid);
      _savedPassword = std::move(password);
      _credentialCacheStatus = CredentialCacheStatus::Valid;
      return true;
    case CredentialStore::Status::NotFound:
      clearCredentialCache(CredentialCacheStatus::NotFound);
      return false;
    case CredentialStore::Status::Corrupt:
      clearCredentialCache(CredentialCacheStatus::Corrupt);
      return false;
    case CredentialStore::Status::Unavailable:
      clearCredentialCache(CredentialCacheStatus::Unavailable);
      log("[PWP] Credential flash region overlaps the program image");
      return false;
  }
  return false;
}

void PicoWiFiPortal::clearCredentialCache(CredentialCacheStatus status) {
  wipe(_savedSSID);
  wipe(_savedPassword);
  _credentialCacheStatus = status;
  _credentialGeneration = credentialGeneration;
}

bool PicoWiFiPortal::hasSavedCredentials() {
  return ensureCredentialCache();
}

std::string PicoWiFiPortal::savedSSID() {
  return ensureCredentialCache() ? _savedSSID : std::string();
}

bool PicoWiFiPortal::eraseCredentials(bool disconnect) {
  const CredentialStore::EraseResult result = _credentialStore.erase();
  // Failed leaves the flash state unknown, so every result invalidates caches.
  ++credentialGeneration;
  bool ok = result == CredentialStore::EraseResult::Erased;
  if (result == CredentialStore::EraseResult::Failed) {
    clearCredentialCache(CredentialCacheStatus::Unknown);
    setError("Unable to commit the credential erase");
  } else {
    clearCredentialCache(CredentialCacheStatus::NotFound);
    if (!ok) {
      setError("Credential erase is incomplete; the erase marker prevents recovery");
    }
  }

  if (disconnect) {
    if (!ensureWiFiOwner()) {
      if (ok) {
        setError("Credentials erased, but Wi-Fi disconnect requires ownership");
      }
      return false;
    }
    cancelAutoReconnect(true);
    stopConfigPortal();
    const bool wasConnected = isConnected();
    if (leaveSTA() != 0 && wasConnected) {
      setError("Credentials erased, but the STA interface did not disconnect");
      _state = State::Failed;
      ok = false;
    } else {
      _staDisconnected = true;
      _state = State::Idle;
    }
  }
  return ok;
}

bool PicoWiFiPortal::setPortalIP(const IPv4Address& localIP) {
  return setPortalIP(localIP, localIP, IPv4Address(255, 255, 255, 0));
}

bool PicoWiFiPortal::setPortalIP(const IPv4Address& localIP,
                                 const IPv4Address& gateway,
                                 const IPv4Address& subnet) {
  if (_portalActive) {
    setError("Portal IP cannot be changed while the portal is active");
    return false;
  }
  const PortalNetworkValidationResult validation = validatePortalNetwork(
      localIP.toUint32(), gateway.toUint32(), subnet.toUint32());
  if (validation != PortalNetworkValidationResult::Valid) {
    setError(portalNetworkValidationMessage(validation));
    return false;
  }

  _portalIP = localIP;
  _portalGateway = gateway;
  _portalSubnet = subnet;
  _lastError.clear();
  return true;
}

bool PicoWiFiPortal::setSTAStaticIP(const IPv4Address& localIP,
                                    const IPv4Address& gateway,
                                    const IPv4Address& subnet,
                                    const IPv4Address& primaryDNS,
                                    const IPv4Address& secondaryDNS) {
  if (_connectPending || _connectAttemptActive) {
    setError("STA IP cannot be changed during a connection attempt");
    return false;
  }
  const uint32_t local = localIP.toUint32();
  const uint32_t gatewayValue = gateway.toUint32();
  const uint32_t primaryDNSValue = primaryDNS.toUint32();
  const uint32_t secondaryDNSValue = secondaryDNS.toUint32();
  if (!isValidSTANetwork(local, gatewayValue, subnet.toUint32()) ||
      local == gatewayValue || !isValidDNSAddress(primaryDNSValue) ||
      !isValidDNSAddress(secondaryDNSValue) ||
      (primaryDNSValue == 0 && secondaryDNSValue != 0)) {
    setError("STA IP, gateway, subnet, or DNS configuration is invalid");
    return false;
  }

  _staIP = localIP;
  _staGateway = gateway;
  _staSubnet = subnet;
  _staPrimaryDNS = primaryDNS;
  _staSecondaryDNS = secondaryDNS;
  _staStaticIPEnabled = true;
  _lastError.clear();
  return true;
}

void PicoWiFiPortal::useSTADHCP() {
  _staStaticIPEnabled = false;
  _staIP = IPv4Address();
  _staGateway = IPv4Address();
  _staSubnet = IPv4Address();
  _staPrimaryDNS = IPv4Address();
  _staSecondaryDNS = IPv4Address();
  _lastError.clear();
}

bool PicoWiFiPortal::isSTAStaticIPConfigured() const {
  return _staStaticIPEnabled;
}

void PicoWiFiPortal::setAutoReconnect(bool enabled) {
  if (!ensureWiFiOwner()) return;
  _autoReconnectEnabled = enabled;
  _lastError.clear();

  if (!enabled) {
    const bool hadActiveReconnect =
        _connectionOwner == ConnectionOwner::Reconnect;
    const bool wasReconnecting =
        _reconnectScheduled || hadActiveReconnect;
    cancelAutoReconnect(true);
    if (wasReconnecting) {
      _state = isConnected() ? State::Connected : State::Idle;
    }
    return;
  }

  if (!_portalActive && !_connectAttemptActive && !isConnected()) {
    _reconnectRetriesUsed = 0;
    scheduleAutoReconnect(_retryIntervalMs);
  }
}

bool PicoWiFiPortal::autoReconnectEnabled() const {
  return _autoReconnectEnabled;
}

bool PicoWiFiPortal::setConnectionRetryPolicy(
    uint8_t retryCount,
    uint32_t retryIntervalMs,
    uint32_t maxRetryIntervalMs) {
  if (retryIntervalMs < 250 || maxRetryIntervalMs < 1000 ||
      maxRetryIntervalMs < retryIntervalMs) {
    setError("Retry interval must be >= 250 ms and maximum >= 1000 ms");
    return false;
  }

  _maxConnectionRetries = retryCount;
  _retryIntervalMs = retryIntervalMs;
  _maxRetryIntervalMs = maxRetryIntervalMs;
  _lastError.clear();
  return true;
}

bool PicoWiFiPortal::setHostname(const char* hostname) {
#if !LWIP_NETIF_HOSTNAME
  (void)hostname;
  setError("setHostname() requires LWIP_NETIF_HOSTNAME in lwipopts.h");
  return false;
#else
  if (_wifiOwned) {
    setError("Hostname must be configured before the first Wi-Fi operation");
    return false;
  }
  if (hostname && strlen(hostname) > 63) {
    setError("Hostname must contain at most 63 bytes");
    return false;
  }

  // lwIP keeps a pointer to this buffer, which is never modified afterwards.
  _hostname = hostname ? hostname : "";
  _lastError.clear();
  return true;
#endif
}

void PicoWiFiPortal::setConnectTimeout(uint32_t timeoutMs) {
  if (timeoutMs == 0) {
    _connectTimeoutMs = kDefaultConnectTimeoutMs;
    log("[PWP] Connect timeout 0 normalized to 15000 ms");
    return;
  }
  _connectTimeoutMs = timeoutMs;
}

void PicoWiFiPortal::setAPChannel(uint8_t channel) {
  if (channel >= 1 && channel <= 13) _apChannel = channel;
}

void PicoWiFiPortal::setLogging(bool enabled) {
  _loggingEnabled = enabled;
}

void PicoWiFiPortal::onPortalStarted(Callback callback) {
  _onPortalStarted = std::move(callback);
}

void PicoWiFiPortal::onCredentialsSaved(Callback callback) {
  _onCredentialsSaved = std::move(callback);
}

void PicoWiFiPortal::onConnected(Callback callback) {
  _onConnected = std::move(callback);
}

bool PicoWiFiPortal::isPortalActive() const {
  return _portalActive;
}

bool PicoWiFiPortal::isPortalConnectionAttemptActive() const {
  return _portalActive &&
         (_connectPending ||
          (_connectAttemptActive &&
           _connectionOwner == ConnectionOwner::Portal));
}

bool PicoWiFiPortal::isConnected() const {
  return _wifiOwned && staLinkStatus() == CYW43_LINK_UP;
}

PicoWiFiPortal::State PicoWiFiPortal::state() const {
  return _state;
}

PicoWiFiPortal::IPv4Address PicoWiFiPortal::portalIP() const {
  return _portalIP;
}

PicoWiFiPortal::IPv4Address PicoWiFiPortal::localIP() const {
  if (!_wifiOwned) return IPv4Address();
  LwipLock lock;
  return IPv4Address::fromUint32(fromLwip(netif_ip4_addr(staNetif())));
}

std::string PicoWiFiPortal::portalSSID() const {
  return _portalSSID;
}

std::string PicoWiFiPortal::lastError() const {
  return _lastError;
}

PicoWiFiPortal::DisconnectReason PicoWiFiPortal::lastDisconnectReason() const {
  return _lastDisconnectReason;
}

const char* PicoWiFiPortal::disconnectReasonName(DisconnectReason reason) {
  switch (reason) {
    case DisconnectReason::None: return "NONE";
    case DisconnectReason::LinkLost: return "LINK_LOST";
    case DisconnectReason::AuthFailed: return "AUTH_FAILED";
    case DisconnectReason::NetworkNotFound: return "NO_AP_FOUND";
    case DisconnectReason::JoinFailed: return "JOIN_FAILED";
    case DisconnectReason::LeftByRequest: return "ASSOC_LEAVE";
  }
  return "UNKNOWN";
}

bool PicoWiFiPortal::validAPPassword(const char* password) const {
  if (!password || strlen(password) == 0) return true;
  const size_t len = strlen(password);
  return len >= 8 && len <= 63;
}

bool PicoWiFiPortal::portalTimedOut() const {
  return _portalTimeoutMs > 0 && (nowMs() - _portalStartedAt >= _portalTimeoutMs);
}

void PicoWiFiPortal::waitForWork(uint32_t timeoutMs) {
  // Sleeps with threadsafe_background; services pending work with poll.
  cyw43_arch_wait_for_work_until(make_timeout_time_ms(timeoutMs));
  cyw43_arch_poll();
}

void PicoWiFiPortal::setError(std::string_view message) {
  _lastError.assign(message.data(), message.size());
}

void PicoWiFiPortal::invoke(const Callback& callback) {
  if (callback) callback();
}

void PicoWiFiPortal::log(const char* message) const {
  if (_loggingEnabled) printf("%s\n", message);
}

void PicoWiFiPortal::logf(const char* format, ...) const {
  if (!_loggingEnabled) return;
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

void PicoWiFiPortal::logDisconnect(DisconnectReason reason) const {
  logf("[PWP] Disconnect: %u (%s)\n", static_cast<unsigned>(reason),
       disconnectReasonName(reason));
}

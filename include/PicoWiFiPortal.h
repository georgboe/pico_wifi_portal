/**
 * @file PicoWiFiPortal.h
 * @brief RP2040/RP2350 (Pico W / Pico 2 W) Wi-Fi captive portal for the
 *        Pico SDK. Port of ESP32WiFiPortal 2.1.2 by Tran Nguyen Hien.
 *
 * @copyright Copyright (c) 2026 Tran Nguyen Hien. All rights reserved.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "CredentialStore.h"

struct _cyw43_ev_scan_result_t;

namespace pico_wifi_portal_detail {
class HttpRequest;
struct PortalServices;
}  // namespace pico_wifi_portal_detail

// Requirements:
// - cyw43_arch_init() (or cyw43_arch_init_with_country()) must have been called
//   before the first Wi-Fi operation.
// - The application links one pico_cyw43_arch_lwip_* variant and provides an
//   lwipopts.h with LWIP_DHCP, LWIP_UDP, LWIP_TCP and LWIP_NETIF_HOSTNAME.
// - All public methods must be called from the same thread/core that calls
//   process(). Callbacks are invoked from that thread.
class PicoWiFiPortal {
public:
  enum class State : uint8_t {
    Idle,
    Connecting,
    Connected,
    Portal,
    Failed
  };

  // CYW43 exposes link states rather than 802.11 reason codes.
  enum class DisconnectReason : uint8_t {
    None,
    LinkLost,
    AuthFailed,
    NetworkNotFound,
    JoinFailed,
    LeftByRequest
  };

  class IPv4Address {
  public:
    constexpr IPv4Address() : _octets{0, 0, 0, 0} {}
    constexpr IPv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
        : _octets{a, b, c, d} {}

    static constexpr IPv4Address fromUint32(uint32_t value) {
      return IPv4Address(static_cast<uint8_t>(value >> 24),
                         static_cast<uint8_t>(value >> 16),
                         static_cast<uint8_t>(value >> 8),
                         static_cast<uint8_t>(value));
    }

    constexpr uint8_t operator[](size_t index) const { return _octets[index]; }
    constexpr uint32_t toUint32() const {
      return (static_cast<uint32_t>(_octets[0]) << 24) |
             (static_cast<uint32_t>(_octets[1]) << 16) |
             (static_cast<uint32_t>(_octets[2]) << 8) |
             static_cast<uint32_t>(_octets[3]);
    }
    constexpr bool operator==(const IPv4Address& other) const {
      return toUint32() == other.toUint32();
    }
    constexpr bool operator!=(const IPv4Address& other) const {
      return !(*this == other);
    }
    std::string toString() const;

  private:
    uint8_t _octets[4];
  };

  using Callback = std::function<void()>;

  PicoWiFiPortal();
  ~PicoWiFiPortal();

  PicoWiFiPortal(const PicoWiFiPortal&) = delete;
  PicoWiFiPortal& operator=(const PicoWiFiPortal&) = delete;

  // Connect using credentials stored by this library in flash.
  // timeoutMs == 0 is normalized to the finite 15000 ms default.
  bool connectSaved(uint32_t timeoutMs = 15000);

  // Convenience startup: try saved Wi-Fi, then optionally open a blocking portal.
  bool autoConnect(const char* apSSID = "Pico-Setup",
                   const char* apPassword = nullptr,
                   uint32_t connectTimeoutMs = 15000,
                   uint32_t portalTimeoutMs = 0);

  // Blocking captive portal. Returns true after successful Wi-Fi connection.
  // portalTimeoutMs == 0 means no portal timeout.
  bool startConfigPortal(const char* apSSID = "Pico-Setup",
                         const char* apPassword = nullptr,
                         uint32_t portalTimeoutMs = 0);

  // Non-blocking captive portal. Call process() frequently from the main loop.
  bool startConfigPortalAsync(const char* apSSID = "Pico-Setup",
                              const char* apPassword = nullptr,
                              uint32_t portalTimeoutMs = 0);

  // Cooperative runtime service. Call frequently; it never waits for a Wi-Fi
  // connection, disconnect settle interval, retry delay, or network scan.
  // With pico_cyw43_arch_lwip_poll it also drives cyw43_arch_poll().
  void process();
  void stopConfigPortal();

  bool isPortalActive() const;
  // True while a Portal candidate is pending, retrying, or connecting on STA.
  bool isPortalConnectionAttemptActive() const;
  bool isConnected() const;
  State state() const;

  // Credential management.
  bool hasSavedCredentials();
  std::string savedSSID();
  bool eraseCredentials(bool disconnect = true);

  // Optional tuning.
  // Accepts usable unicast IPv4 addresses (legacy Class A/B/C ranges). The
  // one-argument overload uses localIP as gateway and a /24 subnet. Explicit
  // Portal subnets are limited to /24.../28 for the built-in DHCP server.
  // Portal addressing can only be changed while the portal is stopped.
  bool setPortalIP(const IPv4Address& localIP);
  bool setPortalIP(const IPv4Address& localIP,
                   const IPv4Address& gateway,
                   const IPv4Address& subnet);

  // Optional static IPv4 configuration for the STA interface. DHCP remains
  // the default and can be restored with useSTADHCP(). Changes apply to the
  // next library-managed connection attempt.
  bool setSTAStaticIP(const IPv4Address& localIP,
                      const IPv4Address& gateway,
                      const IPv4Address& subnet,
                      const IPv4Address& primaryDNS = IPv4Address(),
                      const IPv4Address& secondaryDNS = IPv4Address());
  void useSTADHCP();
  bool isSTAStaticIPConfigured() const;

  // Library-managed reconnect is processed by process(). The retry count is
  // the number of retries after the first attempt. Reconnects enter a capped
  // cooldown after a retry burst, including ambiguous authentication failures.
  void setAutoReconnect(bool enabled);
  bool autoReconnectEnabled() const;
  bool setConnectionRetryPolicy(uint8_t retryCount,
                                uint32_t retryIntervalMs,
                                uint32_t maxRetryIntervalMs);

  // Configure before the first Wi-Fi operation. At most 63 bytes.
  bool setHostname(const char* hostname);
  void setConnectTimeout(uint32_t timeoutMs);
  // CYW43 has a single radio: while STA is associated the AP follows the
  // STA channel regardless of this setting.
  void setAPChannel(uint8_t channel);
  void setLogging(bool enabled);

  // Event callbacks.
  void onPortalStarted(Callback callback);
  void onCredentialsSaved(Callback callback);
  void onConnected(Callback callback);

  IPv4Address portalIP() const;
  IPv4Address localIP() const;
  std::string portalSSID() const;
  std::string lastError() const;
  DisconnectReason lastDisconnectReason() const;
  static const char* disconnectReasonName(DisconnectReason reason);

private:
#if defined(PICO_WIFI_PORTAL_ENABLE_TEST_ACCESS)
  // Host tests exercise the exact private implementation used at runtime.
  friend struct PicoWiFiPortalTestAccess;
#endif

  using HttpRequest = pico_wifi_portal_detail::HttpRequest;
  using CredentialStore = pico_wifi_portal_detail::CredentialStore;

  enum class PortalNetworkValidationResult : uint8_t {
    Valid,
    InvalidLocalIP,
    InvalidGateway,
    InvalidSubnetMask,
    UnsupportedSubnet,
    DifferentSubnet,
    LocalIsNetworkAddress,
    LocalIsBroadcastAddress,
    GatewayIsNetworkAddress,
    GatewayIsBroadcastAddress,
    LocalConflictsWithDHCPLease,
    GatewayConflictsWithDHCPLease
  };

  enum class ConnectionOwner : uint8_t {
    None,
    Blocking,
    Portal,
    Reconnect
  };

  enum class ConnectionPhase : uint8_t {
    Idle,
    Settling,
    Connecting
  };

  enum class ScanState : uint8_t {
    Idle,
    Scanning,
    Ready,
    Failed
  };

  enum class CredentialCacheStatus : uint8_t {
    Unknown,
    Valid,
    NotFound,
    Corrupt,
    // The configured flash region overlaps the program image.
    Unavailable
  };

  struct ScanResult {
    char ssid[33];
    int16_t rssi;
    bool open;
  };

  static constexpr uint16_t kDnsPort = 53;
  static constexpr uint16_t kHttpPort = 80;
  static constexpr uint32_t kDefaultConnectTimeoutMs = 15000;
  static constexpr uint32_t kSTADisconnectSettleMs = 20;
  static constexpr uint32_t kScanTimeoutMs = 15000;
  static constexpr uint32_t kRestartDelayMs = 350;
  static constexpr size_t kMaxScanResults = 24;
  static constexpr uint32_t kDHCPLeaseCount = 11;

  // Allocation-free IPv4 helpers shared by Portal and STA validation. The
  // built-in DHCP server uses the same lease range, so validation is exact.
  static inline bool isUsableUnicastIPv4(uint32_t address) {
    const uint8_t firstOctet = static_cast<uint8_t>(address >> 24);
    return address != 0 && address != 0xFFFFFFFFUL && firstOctet != 0 &&
           firstOctet != 127 && firstOctet < 224;
  }

  static inline bool isContiguousSubnetMask(uint32_t mask) {
    if (mask == 0 || mask == 0xFFFFFFFFUL) return false;
    const uint32_t hostMask = ~mask;
    return (hostMask & (hostMask + 1UL)) == 0;
  }

  static inline uint8_t subnetPrefixLength(uint32_t mask) {
    uint8_t prefixLength = 0;
    while ((mask & 0x80000000UL) != 0) {
      ++prefixLength;
      mask <<= 1;
    }
    return prefixLength;
  }

  static inline uint32_t networkAddress(uint32_t address, uint32_t mask) {
    return address & mask;
  }

  static inline uint32_t broadcastAddress(uint32_t address, uint32_t mask) {
    return networkAddress(address, mask) | ~mask;
  }

  static inline uint32_t defaultDHCPLeaseStart(uint32_t local,
                                               uint32_t mask) {
    const uint32_t hostMask = ~mask;
    const uint32_t candidate = local + 1UL;
    // Keep eleven inclusive addresses for the SoftAP DHCP server and move an
    // overflowing default range to network + 1.
    return ((candidate & hostMask) >= hostMask - (kDHCPLeaseCount - 1))
               ? networkAddress(local, mask) + 1UL
               : candidate;
  }

  static inline bool isSameSubnet(uint32_t first,
                                  uint32_t second,
                                  uint32_t mask) {
    return (first & mask) == (second & mask);
  }

  static inline bool isInInclusiveRange(uint32_t address,
                                        uint32_t first,
                                        uint32_t last) {
    return address >= first && address <= last;
  }

  static inline PortalNetworkValidationResult validatePortalNetwork(
      uint32_t local,
      uint32_t gateway,
      uint32_t mask) {
    if (!isUsableUnicastIPv4(local)) {
      return PortalNetworkValidationResult::InvalidLocalIP;
    }
    if (!isUsableUnicastIPv4(gateway)) {
      return PortalNetworkValidationResult::InvalidGateway;
    }
    if (!isContiguousSubnetMask(mask)) {
      return PortalNetworkValidationResult::InvalidSubnetMask;
    }

    const uint8_t prefixLength = subnetPrefixLength(mask);
    if (prefixLength < 24 || prefixLength > 28) {
      return PortalNetworkValidationResult::UnsupportedSubnet;
    }
    if (!isSameSubnet(local, gateway, mask)) {
      return PortalNetworkValidationResult::DifferentSubnet;
    }

    const uint32_t network = networkAddress(local, mask);
    const uint32_t broadcast = broadcastAddress(local, mask);
    if (local == network) {
      return PortalNetworkValidationResult::LocalIsNetworkAddress;
    }
    if (local == broadcast) {
      return PortalNetworkValidationResult::LocalIsBroadcastAddress;
    }
    if (gateway == network) {
      return PortalNetworkValidationResult::GatewayIsNetworkAddress;
    }
    if (gateway == broadcast) {
      return PortalNetworkValidationResult::GatewayIsBroadcastAddress;
    }

    const uint32_t leaseStart = defaultDHCPLeaseStart(local, mask);
    const uint32_t leaseEnd = leaseStart + (kDHCPLeaseCount - 1);
    if (isInInclusiveRange(local, leaseStart, leaseEnd)) {
      return PortalNetworkValidationResult::LocalConflictsWithDHCPLease;
    }
    if (isInInclusiveRange(gateway, leaseStart, leaseEnd)) {
      return PortalNetworkValidationResult::GatewayConflictsWithDHCPLease;
    }

    return PortalNetworkValidationResult::Valid;
  }

  // STA static addressing intentionally has no SoftAP /24.../28 restriction.
  static inline bool isValidSTANetwork(uint32_t local,
                                       uint32_t gateway,
                                       uint32_t mask) {
    if (!isUsableUnicastIPv4(local) ||
        !isUsableUnicastIPv4(gateway) ||
        !isContiguousSubnetMask(mask) ||
        !isSameSubnet(local, gateway, mask)) {
      return false;
    }
    const uint32_t network = networkAddress(local, mask);
    const uint32_t broadcast = broadcastAddress(local, mask);
    return local != network && local != broadcast && gateway != network &&
           gateway != broadcast;
  }

  static inline bool isValidDNSAddress(uint32_t address) {
    return address == 0 || isUsableUnicastIPv4(address);
  }

  static const char* portalNetworkValidationMessage(
      PortalNetworkValidationResult result);

  bool openPortal(const char* apSSID, const char* apPassword, uint32_t portalTimeoutMs);
  bool failPortalStart(const char* message);
  void shutdownPortal();
  static void dispatchRequest(void* context, HttpRequest& request);
  void handleRequest(HttpRequest& request);
  void handleRoot(HttpRequest& request);
  void handleScan(HttpRequest& request);
  void handleSave(HttpRequest& request);
  void handleStatus(HttpRequest& request);
  void handleProperties(HttpRequest& request);
  void handleReset(HttpRequest& request);
  void handleCaptiveProbe(HttpRequest& request);
  bool startScan();
  void processScan();
  void resetScan();
  static int onScanResult(void* env, const struct _cyw43_ev_scan_result_t* result);
  void beginPendingConnection();
  void clearPendingConnection(bool disconnectSTA);
  void failPendingConnection(bool terminalFailure);

  bool connect(uint32_t timeoutMs);
  bool beginSTAConnection(ConnectionOwner owner);
  bool advanceSTAConnection();
  bool applySTAConfig();
  void releaseSTAConnection();
  void cancelSTAConnection();
  int leaveSTA();
  int staLinkStatus() const;
  bool ensureWiFiOwner();
  void processWiFiEvents();
  void processAutoReconnect();
  void scheduleAutoReconnect(uint32_t delayMs);
  void scheduleNextAutoReconnect();
  void cancelAutoReconnect(bool disconnectSTA);
  bool scheduleSavedConnectionRecovery();
  uint32_t retryDelay(uint8_t retryNumber) const;
  bool saveCredentials(const std::string& ssid, const std::string& password);
  bool ensureCredentialCache();
  void clearCredentialCache(CredentialCacheStatus status);
  bool validAPPassword(const char* password) const;
  bool portalTimedOut() const;
  void waitForWork(uint32_t timeoutMs);
  void setError(std::string_view message);
  void invoke(const Callback& callback);
  void log(const char* message) const;
  void logf(const char* format, ...) const __attribute__((format(printf, 2, 3)));
  void logDisconnect(DisconnectReason reason) const;

  CredentialStore _credentialStore;
  std::unique_ptr<pico_wifi_portal_detail::PortalServices> _services;

  State _state = State::Idle;
  ConnectionOwner _connectionOwner = ConnectionOwner::None;
  ConnectionPhase _connectionPhase = ConnectionPhase::Idle;
  bool _wifiOwned = false;
  bool _apEnabled = false;
  bool _portalActive = false;
  bool _connectPending = false;
  bool _connectAttemptActive = false;
  bool _attemptTerminalFailure = false;
  bool _attemptEnded = false;
  bool _staDisconnected = false;
  bool _expectingLocalDisconnect = false;
  bool _restartPending = false;

  uint32_t _connectTimeoutMs = kDefaultConnectTimeoutMs;
  uint32_t _portalTimeoutMs = 0;
  uint32_t _portalStartedAt = 0;
  uint32_t _connectPendingAt = 0;
  uint32_t _connectAttemptAt = 0;
  uint32_t _connectPendingDelayMs = 350;
  uint32_t _connectionPhaseAt = 0;
  uint32_t _connectionSettleDelayMs = 0;
  uint32_t _restartRequestedAt = 0;

  uint8_t _maxConnectionRetries = 0;
  uint8_t _portalRetriesUsed = 0;
  uint32_t _retryIntervalMs = 1000;
  uint32_t _maxRetryIntervalMs = 60000;

  bool _autoReconnectEnabled = true;
  bool _reconnectScheduled = false;
  uint8_t _reconnectRetriesUsed = 0;
  uint32_t _reconnectScheduledAt = 0;
  uint32_t _reconnectDelayMs = 0;

  uint8_t _apChannel = 1;
  bool _loggingEnabled = true;

  IPv4Address _portalIP;
  IPv4Address _portalGateway;
  IPv4Address _portalSubnet;

  bool _staStaticIPEnabled = false;
  IPv4Address _staIP;
  IPv4Address _staGateway;
  IPv4Address _staSubnet;
  IPv4Address _staPrimaryDNS;
  IPv4Address _staSecondaryDNS;

  int _lastLinkStatus = 0;
  DisconnectReason _lastDisconnectReason = DisconnectReason::None;

  std::string _hostname;
  std::string _portalSSID;
  std::string _pendingSSID;
  std::string _pendingPassword;
  std::string _savedSSID;
  std::string _savedPassword;
  CredentialCacheStatus _credentialCacheStatus =
      CredentialCacheStatus::Unknown;
  // Value of credentialGeneration that _credentialCacheStatus reflects.
  uint32_t _credentialGeneration = 0;

  std::string _responseBuffer;
  std::string _redirectURL;
  // Written by the CYW43 scan callback (async context) and read with the
  // lwIP/async-context lock held, so no heap use happens in that callback.
  ScanResult _scanResults[kMaxScanResults] = {};
  size_t _scanResultCount = 0;
  bool _scanAccepting = false;
  ScanState _scanState = ScanState::Idle;
  uint32_t _scanStartedAt = 0;

  std::string _lastError;

  Callback _onPortalStarted;
  Callback _onCredentialsSaved;
  Callback _onConnected;
};

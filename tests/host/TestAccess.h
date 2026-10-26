#pragma once

#include <PicoWiFiPortal.h>

#include <cstdint>
#include <string>

struct PicoWiFiPortalTestAccess {
  using Result = PicoWiFiPortal::PortalNetworkValidationResult;
  using CredentialStatus = PicoWiFiPortal::CredentialCacheStatus;
  using State = PicoWiFiPortal::State;
  using Store = pico_wifi_portal_detail::CredentialStore;

  static uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
  }

  // --- IPv4 helpers --------------------------------------------------------

  static Result validate(uint32_t local, uint32_t gateway, uint32_t mask) {
    return PicoWiFiPortal::validatePortalNetwork(local, gateway, mask);
  }

  static bool usable(uint32_t address) {
    return PicoWiFiPortal::isUsableUnicastIPv4(address);
  }

  static bool contiguous(uint32_t mask) {
    return PicoWiFiPortal::isContiguousSubnetMask(mask);
  }

  static uint8_t prefix(uint32_t mask) {
    return PicoWiFiPortal::subnetPrefixLength(mask);
  }

  static bool sameSubnet(uint32_t first, uint32_t second, uint32_t mask) {
    return PicoWiFiPortal::isSameSubnet(first, second, mask);
  }

  static uint32_t network(uint32_t address, uint32_t mask) {
    return PicoWiFiPortal::networkAddress(address, mask);
  }

  static uint32_t broadcast(uint32_t address, uint32_t mask) {
    return PicoWiFiPortal::broadcastAddress(address, mask);
  }

  static uint32_t dhcpLeaseStart(uint32_t local, uint32_t mask) {
    return PicoWiFiPortal::defaultDHCPLeaseStart(local, mask);
  }

  static bool validSTANetwork(uint32_t local, uint32_t gateway,
                              uint32_t mask) {
    return PicoWiFiPortal::isValidSTANetwork(local, gateway, mask);
  }

  // --- Portal state --------------------------------------------------------

  static const std::string& redirectURL(const PicoWiFiPortal& portal) {
    return portal._redirectURL;
  }

  static bool saveCredentials(PicoWiFiPortal& portal, const std::string& ssid,
                              const std::string& password) {
    return portal.saveCredentials(ssid, password);
  }

  static CredentialStatus credentialStatus(const PicoWiFiPortal& portal) {
    return portal._credentialCacheStatus;
  }

  static const std::string& savedPassword(const PicoWiFiPortal& portal) {
    return portal._savedPassword;
  }

  static const std::string& pendingSSID(const PicoWiFiPortal& portal) {
    return portal._pendingSSID;
  }

  static const std::string& pendingPassword(const PicoWiFiPortal& portal) {
    return portal._pendingPassword;
  }

  static bool connectPending(const PicoWiFiPortal& portal) {
    return portal._connectPending;
  }

  static bool restartPending(const PicoWiFiPortal& portal) {
    return portal._restartPending;
  }

  static uint32_t restartRequestedAt(const PicoWiFiPortal& portal) {
    return portal._restartRequestedAt;
  }

  static uint32_t restartDelay() { return PicoWiFiPortal::kRestartDelayMs; }

  static uint32_t scanTimeout() { return PicoWiFiPortal::kScanTimeoutMs; }

  static size_t maxScanResults() { return PicoWiFiPortal::kMaxScanResults; }

  static uint32_t settleDelay() {
    return PicoWiFiPortal::kSTADisconnectSettleMs;
  }

  static uint32_t connectTimeout(const PicoWiFiPortal& portal) {
    return portal._connectTimeoutMs;
  }

  static bool reconnectScheduled(const PicoWiFiPortal& portal) {
    return portal._reconnectScheduled;
  }

  static uint8_t reconnectRetriesUsed(const PicoWiFiPortal& portal) {
    return portal._reconnectRetriesUsed;
  }

  static uint32_t reconnectDelay(const PicoWiFiPortal& portal) {
    return portal._reconnectDelayMs;
  }

  static uint32_t connectAttemptAt(const PicoWiFiPortal& portal) {
    return portal._connectAttemptAt;
  }

  static bool connectAttemptActive(const PicoWiFiPortal& portal) {
    return portal._connectAttemptActive;
  }

  static bool reconnectAttemptActive(const PicoWiFiPortal& portal) {
    return portal._connectAttemptActive &&
           portal._connectionOwner ==
               PicoWiFiPortal::ConnectionOwner::Reconnect;
  }

  static bool portalAttemptActive(const PicoWiFiPortal& portal) {
    return portal._connectAttemptActive &&
           portal._connectionOwner == PicoWiFiPortal::ConnectionOwner::Portal;
  }

  static uint8_t portalRetriesUsed(const PicoWiFiPortal& portal) {
    return portal._portalRetriesUsed;
  }

  static uint32_t retryDelay(const PicoWiFiPortal& portal, uint8_t retry) {
    return portal.retryDelay(retry);
  }

  static bool servicesAllocated(const PicoWiFiPortal& portal) {
    return static_cast<bool>(portal._services);
  }

  // --- CredentialStore -----------------------------------------------------

  static constexpr size_t recordSize() { return Store::kRecordSize; }
  static constexpr size_t slotSize() { return Store::kSlotSize; }
  static constexpr size_t slotHeaderSize() { return Store::kSlotHeaderSize; }
  static constexpr size_t slotCRCOffset() { return Store::kSlotCRCOffset; }
  static constexpr uint8_t slotKindCredential() {
    return Store::kSlotKindCredential;
  }
  static constexpr uint8_t slotKindErased() { return Store::kSlotKindErased; }

  // Offset of credential slot index (0 or 1) from the start of flash.
  static uint32_t slotOffset(size_t index) { return Store::slotOffset(index); }

  static uint32_t crc32(const uint8_t* data, size_t length) {
    return Store::crc32(data, length);
  }

  static bool serializeRecord(const std::string& ssid,
                              const std::string& password, uint8_t* record) {
    return Store::serializeRecord(ssid, password, record);
  }

  static bool deserializeRecord(const uint8_t* record, std::string& ssid,
                                std::string& password) {
    return Store::deserializeRecord(record, ssid, password);
  }
};

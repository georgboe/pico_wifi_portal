/**
 * @file CredentialStore.h
 * @brief Power-loss-safe Wi-Fi credential storage in RP2040/RP2350 flash.
 *
 * @copyright Copyright (c) 2026 Tran Nguyen Hien. All rights reserved.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// Two consecutive 4 KiB flash sectors hold the A/B credential slots. The
// default leaves the last two sectors free for BTstack's flash bank storage.
#ifndef PICO_WIFI_PORTAL_FLASH_OFFSET
#define PICO_WIFI_PORTAL_FLASH_OFFSET (PICO_FLASH_SIZE_BYTES - 4u * 4096u)
#endif

#if defined(PICO_WIFI_PORTAL_ENABLE_TEST_ACCESS)
struct PicoWiFiPortalTestAccess;
#endif

namespace pico_wifi_portal_detail {

// Each slot carries a sequence number and CRC. Writes always go to the slot
// that is not the newest valid one, so a reset during erase/program leaves the
// previous committed value in place. Erase commits a tombstone first, so an
// interrupted erase can never resurrect old credentials.
class CredentialStore {
public:
  enum class Status : uint8_t {
    Valid,
    NotFound,
    Corrupt,
    Unavailable
  };

  enum class EraseResult : uint8_t {
    Erased,
    // The tombstone is committed but the old record is still physically
    // present in flash; it can never be loaded again.
    Incomplete,
    Failed
  };

  static constexpr size_t kSSIDCapacity = 33;
  static constexpr size_t kPasswordCapacity = 65;

  // False if the configured region overlaps the program image or flash end.
  static bool regionUsable();

  Status load(std::string& ssid, std::string& password) const;
  bool save(const std::string& ssid, const std::string& password);
  EraseResult erase();

  static bool validCredentials(const std::string& ssid,
                               const std::string& password);
  static void secureClear(void* data, size_t length);

private:
#if defined(PICO_WIFI_PORTAL_ENABLE_TEST_ACCESS)
  friend struct ::PicoWiFiPortalTestAccess;
#endif

  static constexpr uint32_t kRecordMagic = 0x43505745UL;  // "EWPC"
  static constexpr uint16_t kRecordVersion = 1;
  static constexpr size_t kSSIDOffset = 10;
  static constexpr size_t kPasswordOffset = kSSIDOffset + kSSIDCapacity;
  static constexpr size_t kRecordCRCOffset = kPasswordOffset + kPasswordCapacity;
  static constexpr size_t kRecordSize = kRecordCRCOffset + 4;
  static_assert(kRecordSize == 112, "Credential record layout changed unexpectedly");

  static constexpr uint32_t kSlotMagic = 0x53505750UL;  // "PWPS"
  static constexpr uint8_t kSlotKindCredential = 1;
  static constexpr uint8_t kSlotKindErased = 2;
  static constexpr size_t kSlotHeaderSize = 12;
  static constexpr size_t kSlotCRCOffset = kSlotHeaderSize + kRecordSize;
  static constexpr size_t kSlotSize = kSlotCRCOffset + 4;
  static constexpr size_t kSlotCount = 2;
  static_assert(kSlotSize <= 256, "A credential slot must fit in one flash page");

  struct SlotInfo {
    bool valid;
    bool blank;
    uint32_t sequence;
    uint8_t kind;
    const uint8_t* data;
  };

  static uint32_t crc32(const uint8_t* data, size_t length);
  static bool isValidRawPSK(const std::string& password);
  static bool serializeRecord(const std::string& ssid,
                              const std::string& password,
                              uint8_t* record);
  static bool deserializeRecord(const uint8_t* record,
                                std::string& ssid,
                                std::string& password);
  static uint32_t slotOffset(size_t index);
  static SlotInfo readSlot(size_t index);
  static int newestSlot(const SlotInfo* slots);
  static bool writeSlot(size_t index, uint32_t sequence, uint8_t kind,
                        const uint8_t* record);
  static bool eraseSlot(size_t index);
};

}  // namespace pico_wifi_portal_detail

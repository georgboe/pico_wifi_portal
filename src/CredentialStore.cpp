/**
 * @file CredentialStore.cpp
 * @brief Power-loss-safe Wi-Fi credential storage in RP2040/RP2350 flash.
 *
 * @copyright Copyright (c) 2026 Tran Nguyen Hien. All rights reserved.
 */

#include "CredentialStore.h"

#include <cstring>

#include "hardware/flash.h"
#include "pico/flash.h"
#include "pico/stdlib.h"

extern "C" char __flash_binary_end;

namespace pico_wifi_portal_detail {

namespace {
constexpr uint32_t kFlashSafeTimeoutMs = 1000;

struct FlashJob {
  uint32_t offset;
  const uint8_t* page;
};

// Runs with interrupts disabled (and the other core locked out when
// multicore lockout is enabled), as required while XIP is unavailable.
void runFlashJob(void* param) {
  const FlashJob* job = static_cast<const FlashJob*>(param);
  flash_range_erase(job->offset, FLASH_SECTOR_SIZE);
  if (job->page) flash_range_program(job->offset, job->page, FLASH_PAGE_SIZE);
}

uint32_t readLE32(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}

void writeLE32(uint8_t* data, uint32_t value) {
  data[0] = static_cast<uint8_t>(value);
  data[1] = static_cast<uint8_t>(value >> 8);
  data[2] = static_cast<uint8_t>(value >> 16);
  data[3] = static_cast<uint8_t>(value >> 24);
}
}  // namespace

static_assert(PICO_WIFI_PORTAL_FLASH_OFFSET % FLASH_SECTOR_SIZE == 0,
              "PICO_WIFI_PORTAL_FLASH_OFFSET must be sector aligned");

bool CredentialStore::regionUsable() {
  const uintptr_t binaryEnd =
      reinterpret_cast<uintptr_t>(&__flash_binary_end) - XIP_BASE;
  return PICO_WIFI_PORTAL_FLASH_OFFSET >= binaryEnd &&
         PICO_WIFI_PORTAL_FLASH_OFFSET + kSlotCount * FLASH_SECTOR_SIZE <=
             PICO_FLASH_SIZE_BYTES;
}

uint32_t CredentialStore::slotOffset(size_t index) {
  return PICO_WIFI_PORTAL_FLASH_OFFSET + index * FLASH_SECTOR_SIZE;
}

CredentialStore::SlotInfo CredentialStore::readSlot(size_t index) {
  const uint8_t* data =
      reinterpret_cast<const uint8_t*>(XIP_BASE + slotOffset(index));
  SlotInfo slot = {false, true, 0, 0, data};
  for (size_t i = 0; i < kSlotSize; ++i) {
    if (data[i] != 0xFF) {
      slot.blank = false;
      break;
    }
  }
  if (slot.blank) return slot;

  slot.sequence = readLE32(data + 4);
  slot.kind = data[8];
  slot.valid = readLE32(data) == kSlotMagic &&
               (slot.kind == kSlotKindCredential ||
                slot.kind == kSlotKindErased) &&
               readLE32(data + kSlotCRCOffset) == crc32(data, kSlotCRCOffset);
  return slot;
}

int CredentialStore::newestSlot(const SlotInfo* slots) {
  if (slots[0].valid && slots[1].valid) {
    // Serial-number arithmetic keeps ordering correct across wrap-around.
    return static_cast<int32_t>(slots[1].sequence - slots[0].sequence) > 0 ? 1
                                                                           : 0;
  }
  if (slots[0].valid) return 0;
  if (slots[1].valid) return 1;
  return -1;
}

bool CredentialStore::writeSlot(size_t index,
                                uint32_t sequence,
                                uint8_t kind,
                                const uint8_t* record) {
  uint8_t page[FLASH_PAGE_SIZE];
  memset(page, 0xFF, sizeof(page));
  writeLE32(page, kSlotMagic);
  writeLE32(page + 4, sequence);
  page[8] = kind;
  page[9] = 0;
  page[10] = 0;
  page[11] = 0;
  if (record) {
    memcpy(page + kSlotHeaderSize, record, kRecordSize);
  } else {
    memset(page + kSlotHeaderSize, 0, kRecordSize);
  }
  writeLE32(page + kSlotCRCOffset, crc32(page, kSlotCRCOffset));

  FlashJob job = {slotOffset(index), page};
  const bool written =
      flash_safe_execute(runFlashJob, &job, kFlashSafeTimeoutMs) == PICO_OK;
  const uint8_t* stored =
      reinterpret_cast<const uint8_t*>(XIP_BASE + slotOffset(index));
  const bool verified = written && memcmp(stored, page, kSlotSize) == 0;
  secureClear(page, sizeof(page));
  return verified;
}

bool CredentialStore::eraseSlot(size_t index) {
  FlashJob job = {slotOffset(index), nullptr};
  if (flash_safe_execute(runFlashJob, &job, kFlashSafeTimeoutMs) != PICO_OK) {
    return false;
  }
  return readSlot(index).blank;
}

CredentialStore::Status CredentialStore::load(std::string& ssid,
                                              std::string& password) const {
  if (!regionUsable()) return Status::Unavailable;

  const SlotInfo slots[kSlotCount] = {readSlot(0), readSlot(1)};
  const int newest = newestSlot(slots);
  if (newest < 0) {
    // A torn first write is indistinguishable from damage, so fail closed.
    return slots[0].blank && slots[1].blank ? Status::NotFound
                                            : Status::Corrupt;
  }
  if (slots[newest].kind == kSlotKindErased) return Status::NotFound;
  return deserializeRecord(slots[newest].data + kSlotHeaderSize, ssid, password)
             ? Status::Valid
             : Status::Corrupt;
}

bool CredentialStore::save(const std::string& ssid,
                           const std::string& password) {
  if (!regionUsable()) return false;

  uint8_t record[kRecordSize];
  if (!serializeRecord(ssid, password, record)) {
    secureClear(record, sizeof(record));
    return false;
  }

  const SlotInfo slots[kSlotCount] = {readSlot(0), readSlot(1)};
  const int newest = newestSlot(slots);
  if (newest >= 0 && slots[newest].kind == kSlotKindCredential &&
      memcmp(slots[newest].data + kSlotHeaderSize, record, kRecordSize) == 0) {
    // Unchanged credentials do not cost a flash erase cycle.
    secureClear(record, sizeof(record));
    return true;
  }

  const size_t target = newest < 0 ? 0 : 1 - static_cast<size_t>(newest);
  const uint32_t sequence = newest < 0 ? 1 : slots[newest].sequence + 1;
  const bool committed =
      writeSlot(target, sequence, kSlotKindCredential, record);
  secureClear(record, sizeof(record));
  if (committed && !slots[1 - target].blank) {
    // The superseded record is only a recovery point until the new slot has
    // been verified. Failure here is harmless: the newer sequence wins.
    eraseSlot(1 - target);
  }
  return committed;
}

CredentialStore::EraseResult CredentialStore::erase() {
  if (!regionUsable()) return EraseResult::Failed;

  const SlotInfo slots[kSlotCount] = {readSlot(0), readSlot(1)};
  const int newest = newestSlot(slots);
  if (newest < 0) {
    if (slots[0].blank && slots[1].blank) return EraseResult::Erased;
    // Neither slot can be loaded; scrub both so torn data cannot linger.
    const bool scrubbed = (slots[0].blank || eraseSlot(0)) &&
                          (slots[1].blank || eraseSlot(1));
    return scrubbed ? EraseResult::Erased : EraseResult::Failed;
  }

  const size_t other = 1 - static_cast<size_t>(newest);
  if (slots[newest].kind == kSlotKindErased && slots[other].blank) {
    return EraseResult::Erased;
  }

  size_t stale = static_cast<size_t>(newest);
  if (slots[newest].kind != kSlotKindErased) {
    // Commit the erase intent before removing any credential bytes.
    if (!writeSlot(other, slots[newest].sequence + 1, kSlotKindErased,
                   nullptr)) {
      return EraseResult::Failed;
    }
  } else {
    stale = other;
  }
  return eraseSlot(stale) ? EraseResult::Erased : EraseResult::Incomplete;
}

bool CredentialStore::validCredentials(const std::string& ssid,
                                       const std::string& password) {
  const size_t ssidLength = ssid.length();
  const size_t passwordLength = password.length();
  if (ssidLength == 0 || ssidLength > 32 || passwordLength > 64 ||
      (passwordLength > 0 && passwordLength < 8)) {
    return false;
  }
  if (passwordLength == 64 && !isValidRawPSK(password)) return false;

  // The CYW43 join API consumes C strings, so embedded NUL bytes cannot be
  // stored as part of an exact credential value.
  return ssid.find('\0') == std::string::npos &&
         password.find('\0') == std::string::npos;
}

bool CredentialStore::isValidRawPSK(const std::string& password) {
  if (password.length() != 64) return false;
  for (const char character : password) {
    const bool hexadecimal =
        (character >= '0' && character <= '9') ||
        (character >= 'a' && character <= 'f') ||
        (character >= 'A' && character <= 'F');
    if (!hexadecimal) return false;
  }
  return true;
}

uint32_t CredentialStore::crc32(const uint8_t* data, size_t length) {
  uint32_t crc = 0xFFFFFFFFUL;
  for (size_t i = 0; i < length; ++i) {
    crc ^= data[i];
    for (uint8_t bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1) ^ ((crc & 1U) ? 0xEDB88320UL : 0UL);
    }
  }
  return crc ^ 0xFFFFFFFFUL;
}

bool CredentialStore::serializeRecord(const std::string& ssid,
                                      const std::string& password,
                                      uint8_t* record) {
  if (!record || !validCredentials(ssid, password)) return false;

  memset(record, 0, kRecordSize);
  writeLE32(record, kRecordMagic);
  record[4] = static_cast<uint8_t>(kRecordVersion);
  record[5] = static_cast<uint8_t>(kRecordVersion >> 8);
  record[6] = static_cast<uint8_t>(kRecordSize);
  record[7] = static_cast<uint8_t>(kRecordSize >> 8);
  record[8] = static_cast<uint8_t>(ssid.length());
  record[9] = static_cast<uint8_t>(password.length());
  memcpy(record + kSSIDOffset, ssid.data(), ssid.length());
  memcpy(record + kPasswordOffset, password.data(), password.length());
  writeLE32(record + kRecordCRCOffset, crc32(record, kRecordCRCOffset));
  return true;
}

bool CredentialStore::deserializeRecord(const uint8_t* record,
                                        std::string& ssid,
                                        std::string& password) {
  if (!record) return false;

  const uint16_t version = static_cast<uint16_t>(record[4]) |
                           (static_cast<uint16_t>(record[5]) << 8);
  const uint16_t encodedSize = static_cast<uint16_t>(record[6]) |
                               (static_cast<uint16_t>(record[7]) << 8);
  if (readLE32(record) != kRecordMagic || version != kRecordVersion ||
      encodedSize != kRecordSize ||
      readLE32(record + kRecordCRCOffset) != crc32(record, kRecordCRCOffset)) {
    return false;
  }

  const size_t ssidLength = record[8];
  const size_t passwordLength = record[9];
  if (ssidLength == 0 || ssidLength > 32 || passwordLength > 64 ||
      (passwordLength > 0 && passwordLength < 8)) {
    return false;
  }

  for (size_t i = 0; i < kSSIDCapacity; ++i) {
    if ((i < ssidLength && record[kSSIDOffset + i] == 0) ||
        (i >= ssidLength && record[kSSIDOffset + i] != 0)) {
      return false;
    }
  }
  for (size_t i = 0; i < kPasswordCapacity; ++i) {
    if ((i < passwordLength && record[kPasswordOffset + i] == 0) ||
        (i >= passwordLength && record[kPasswordOffset + i] != 0)) {
      return false;
    }
  }

  ssid.assign(reinterpret_cast<const char*>(record + kSSIDOffset), ssidLength);
  password.assign(reinterpret_cast<const char*>(record + kPasswordOffset),
                  passwordLength);
  return validCredentials(ssid, password);
}

void CredentialStore::secureClear(void* data, size_t length) {
  volatile uint8_t* bytes = static_cast<volatile uint8_t*>(data);
  while (length-- > 0) *bytes++ = 0;
}

}  // namespace pico_wifi_portal_detail

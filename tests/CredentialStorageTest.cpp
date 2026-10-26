#include "host/FakePico.h"
#include "host/TestAccess.h"

#include "host/TestAssert.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

using Access = PicoWiFiPortalTestAccess;
using CredentialStatus = Access::CredentialStatus;
using State = PicoWiFiPortal::State;

std::string repeated(char value, size_t count) {
  return std::string(count, value);
}

uint32_t readLE32(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}

void writeLE32(uint8_t* data, uint32_t value) {
  for (size_t i = 0; i < 4; ++i) {
    data[i] = static_cast<uint8_t>(value >> (8 * i));
  }
}

// Raw view of credential slot index (0 or 1) in the fake flash.
uint8_t* slotBytes(size_t index) {
  return fakeFlashAt(Access::slotOffset(index));
}

uint8_t* recordBytes(uint8_t* slot) {
  return slot + Access::slotHeaderSize();
}

bool slotBlank(size_t index) {
  const uint8_t* slot = slotBytes(index);
  for (size_t i = 0; i < Access::slotSize(); ++i) {
    if (slot[i] != 0xFF) return false;
  }
  return true;
}

uint32_t slotSequence(size_t index) {
  return readLE32(slotBytes(index) + 4);
}

uint8_t slotKind(size_t index) {
  return slotBytes(index)[8];
}

// The slot CRC covers header and record, so every edit needs both repairs
// when the test wants the damage to reach the record parser.
void refreshSlotCRC(uint8_t* slot) {
  const size_t crcOffset = Access::slotCRCOffset();
  writeLE32(slot + crcOffset, Access::crc32(slot, crcOffset));
}

void refreshRecordCRC(uint8_t* record) {
  const size_t crcOffset = Access::recordSize() - 4;
  writeLE32(record + crcOffset, Access::crc32(record, crcOffset));
}

std::vector<uint8_t> makeRecord(const std::string& ssid,
                                const std::string& password) {
  std::vector<uint8_t> record(Access::recordSize());
  assert(Access::serializeRecord(ssid, password, record.data()));
  return record;
}

// Writes a slot image with an arbitrary sequence number, as a test-only way to
// reach states the public API never produces (sequence wrap-around).
// A null record means a tombstone with a zeroed record area.
void writeRawSlot(size_t index, uint32_t sequence, uint8_t kind,
                  const uint8_t* record) {
  std::vector<uint8_t> slot(Access::slotSize(), 0);
  slot[0] = 'P';
  slot[1] = 'W';
  slot[2] = 'P';
  slot[3] = 'S';
  writeLE32(slot.data() + 4, sequence);
  slot[8] = kind;
  if (record) {
    std::memcpy(slot.data() + Access::slotHeaderSize(), record,
                Access::recordSize());
  }
  refreshSlotCRC(slot.data());
  std::memcpy(slotBytes(index), slot.data(), slot.size());
}

// Boots a fresh portal on the current flash and requires exactly this pair.
void expectLoaded(const std::string& ssid, const std::string& password) {
  PicoWiFiPortal portal;
  portal.setLogging(false);
  assert(portal.hasSavedCredentials());
  assert(Access::credentialStatus(portal) == CredentialStatus::Valid);
  assert(portal.savedSSID() == ssid);
  assert(Access::savedPassword(portal) == password);
}

// Boots a fresh portal on the current flash and requires no credentials.
void expectNoCredentials(CredentialStatus status) {
  PicoWiFiPortal portal;
  portal.setLogging(false);
  assert(!portal.hasSavedCredentials());
  assert(Access::credentialStatus(portal) == status);
  assert(portal.savedSSID().empty());
  assert(Access::savedPassword(portal).empty());
}

// Reboots on the current flash, runs auto reconnect once its delay has passed,
// and checks that neither auto reconnect nor connectSaved reaches the driver.
void expectNoConnect(CredentialStatus status, const char* reconnectError,
                     const char* connectError) {
  resetFakeRuntime(true);
  PicoWiFiPortal portal;
  portal.setLogging(false);
  assert(!portal.hasSavedCredentials());
  assert(Access::credentialStatus(portal) == status);

  portal.setAutoReconnect(true);
  FakeMillis = 1000;
  portal.process();
  assert(FakeCyw43.connectCalls == 0);
  assert(!Access::reconnectScheduled(portal));
  assert(portal.state() == State::Failed);
  assert(portal.lastError() == reconnectError);

  assert(!portal.connectSaved(1000));
  assert(FakeCyw43.connectCalls == 0);
  assert(portal.state() == State::Failed);
  assert(portal.lastError() == connectError);
}

void expectCorruptRecordRejected() {
  expectNoConnect(CredentialStatus::Corrupt,
                  "Auto reconnect rejected an unusable credential record",
                  "Saved Wi-Fi credential record is corrupt");
}

// Saves a reference record into slot 0, applies damage to that slot and
// checks that the damaged credentials are rejected before any connect.
template <typename Damage>
void expectDamageRejected(Damage damage) {
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Exact SSID ", "password"));
  }
  assert(!slotBlank(0));
  assert(slotBlank(1));
  damage(slotBytes(0));
  expectCorruptRecordRejected();
}

// Leaves slot 0 holding a torn first write and slot 1 blank.
void makeTornFirstWrite() {
  resetFakeRuntime();
  PicoWiFiPortal portal;
  portal.setLogging(false);
  // 40 programmed bytes stop before the slot CRC at offset 124.
  FakeFlash.programByteBudget = 40;
  assert(!Access::saveCredentials(portal, "Torn SSID", "torn-password"));
  FakeFlash.programByteBudget = -1;
  assert(!slotBlank(0));
  assert(slotBlank(1));
}

}  // namespace

int main() {
  // --- Layout and CRC -------------------------------------------------------
  static const uint8_t kCRCVector[] = "123456789";
  assert(Access::crc32(kCRCVector, 9) == 0xCBF43926UL);
  assert(Access::recordSize() == 112);
  assert(Access::slotHeaderSize() == 12);
  assert(Access::slotCRCOffset() == 124);
  assert(Access::slotSize() == 128);
  // Default region: the last 16 KiB of a 2 MiB flash.
  assert(Access::slotOffset(0) == 0x1FC000);
  assert(Access::slotOffset(1) == 0x1FD000);

  {
    uint8_t scratch[16];
    std::memset(scratch, 0xA5, sizeof(scratch));
    Access::Store::secureClear(scratch, sizeof(scratch));
    for (const uint8_t byte : scratch) assert(byte == 0);
  }

  // --- Validation matrix ----------------------------------------------------
  assert(!Access::Store::validCredentials("", "12345678"));
  assert(!Access::Store::validCredentials(repeated('S', 33), "12345678"));
  assert(Access::Store::validCredentials(repeated('S', 32), repeated('P', 63)));
  assert(Access::Store::validCredentials("Open network", ""));
  assert(Access::Store::validCredentials("ssid", "12345678"));
  assert(!Access::Store::validCredentials("ssid", "1234567"));
  assert(!Access::Store::validCredentials("ssid", repeated('P', 64)));
  assert(Access::Store::validCredentials("raw-psk", repeated('A', 64)));
  assert(Access::Store::validCredentials("raw-psk",
                                         repeated('a', 32) + repeated('F', 32)));
  assert(!Access::Store::validCredentials("ssid", repeated('G', 64)));
  assert(!Access::Store::validCredentials("ssid", repeated('A', 65)));
  assert(!Access::Store::validCredentials(std::string("Net\0x", 5), "12345678"));
  assert(!Access::Store::validCredentials("ssid", std::string("pass\0wor", 8)));

  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(!Access::saveCredentials(portal, "", "12345678"));
    assert(portal.lastError() == "Invalid Wi-Fi credentials");
    assert(!Access::saveCredentials(portal, repeated('S', 33), "12345678"));
    assert(!Access::saveCredentials(portal, "ssid", "1234567"));
    assert(!Access::saveCredentials(portal, "ssid", repeated('P', 64)));
    assert(!Access::saveCredentials(portal, "ssid", repeated('A', 65)));
    // Rejected input never reaches flash.
    assert(FakeFlash.eraseCalls == 0);
    assert(FakeFlash.programCalls == 0);
    assert(FakeFlash.safeExecuteCalls == 0);
    assert(Access::credentialStatus(portal) == CredentialStatus::Unknown);
  }

  // --- Max-length round trip and no-op save ---------------------------------
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    const std::string maxSSID = repeated('S', 32);
    const std::string maxPassword = repeated('P', 63);
    assert(Access::saveCredentials(portal, maxSSID, maxPassword));
    assert(portal.savedSSID() == maxSSID);
    assert(Access::savedPassword(portal) == maxPassword);
    // First save: one sector erase, one page program, one safe execute.
    assert(FakeFlash.eraseCalls == 1);
    assert(FakeFlash.programCalls == 1);
    assert(FakeFlash.safeExecuteCalls == 1);
    assert(!slotBlank(0));
    assert(slotBlank(1));

    const uint32_t erasesBefore = FakeFlash.eraseCalls;
    const uint32_t programsBefore = FakeFlash.programCalls;
    const uint32_t safeBefore = FakeFlash.safeExecuteCalls;
    assert(Access::saveCredentials(portal, maxSSID, maxPassword));
    assert(FakeFlash.eraseCalls == erasesBefore);
    assert(FakeFlash.programCalls == programsBefore);
    assert(FakeFlash.safeExecuteCalls == safeBefore);
  }
  resetFakeRuntime(true);
  expectLoaded(repeated('S', 32), repeated('P', 63));

  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Open network", ""));
  }
  resetFakeRuntime(true);
  expectLoaded("Open network", "");

  // --- Corrupt records --------------------------------------------------------
  // The slot CRC fails first, so the slot is rejected as a whole.
  expectDamageRejected([](uint8_t* slot) {
    slot[Access::slotHeaderSize() + 10] ^= 0x40;
  });
  // Record payload changed, slot CRC repaired, record CRC left stale.
  expectDamageRejected([](uint8_t* slot) {
    recordBytes(slot)[10] ^= 0x40;
    refreshSlotCRC(slot);
  });
  expectDamageRejected([](uint8_t* slot) {
    recordBytes(slot)[0] ^= 1;
    refreshRecordCRC(recordBytes(slot));
    refreshSlotCRC(slot);
  });
  expectDamageRejected([](uint8_t* slot) {
    recordBytes(slot)[4] = 2;
    refreshRecordCRC(recordBytes(slot));
    refreshSlotCRC(slot);
  });
  expectDamageRejected([](uint8_t* slot) {
    recordBytes(slot)[6] = 111;
    refreshRecordCRC(recordBytes(slot));
    refreshSlotCRC(slot);
  });
  expectDamageRejected([](uint8_t* slot) {
    recordBytes(slot)[8] = 33;
    refreshRecordCRC(recordBytes(slot));
    refreshSlotCRC(slot);
  });
  expectDamageRejected([](uint8_t* slot) {
    recordBytes(slot)[8] = 0;
    refreshRecordCRC(recordBytes(slot));
    refreshSlotCRC(slot);
  });
  expectDamageRejected([](uint8_t* slot) {
    recordBytes(slot)[9] = 7;
    refreshRecordCRC(recordBytes(slot));
    refreshSlotCRC(slot);
  });
  expectDamageRejected([](uint8_t* slot) {
    recordBytes(slot)[9] = 65;
    refreshRecordCRC(recordBytes(slot));
    refreshSlotCRC(slot);
  });
  // "Exact SSID " is 11 bytes, so byte 10 + 11 is padding and must be zero.
  expectDamageRejected([](uint8_t* slot) {
    recordBytes(slot)[21] = 'X';
    refreshRecordCRC(recordBytes(slot));
    refreshSlotCRC(slot);
  });
  expectDamageRejected([](uint8_t* slot) {
    slot[0] ^= 1;
  });
  expectDamageRejected([](uint8_t* slot) {
    slot[8] = 3;
    refreshSlotCRC(slot);
  });
  expectDamageRejected([](uint8_t* slot) {
    slot[Access::slotCRCOffset()] ^= 1;
  });

  // --- Not found ------------------------------------------------------------
  resetFakeRuntime();
  expectNoConnect(CredentialStatus::NotFound,
                  "Auto reconnect requires saved Wi-Fi credentials",
                  "No saved Wi-Fi credentials");

  // --- Power loss during an interrupted write -------------------------------
  // Torn new slot: the old credentials remain authoritative after reboot.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Old SSID", "old-password"));
    FakeFlash.programByteBudget = 40;
    assert(!Access::saveCredentials(portal, "New SSID", "new-password"));
    FakeFlash.programByteBudget = -1;
    assert(portal.lastError() ==
           "Unable to commit the Wi-Fi credential transaction");
    assert(portal.savedSSID() == "Old SSID");
    assert(Access::savedPassword(portal) == "old-password");
    assert(!slotBlank(1));
  }
  resetFakeRuntime(true);
  expectLoaded("Old SSID", "old-password");

  // Failure before any flash operation leaves the target slot untouched.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Old SSID", "old-password"));
    FakeFlash.failSafeExecute = 1;
    assert(!Access::saveCredentials(portal, "New SSID", "new-password"));
    assert(slotBlank(1));
    assert(FakeFlash.programCalls == 1);
  }
  resetFakeRuntime(true);
  expectLoaded("Old SSID", "old-password");

  // Reset after the new slot is committed but before the old slot is erased:
  // the newer sequence number wins on reboot.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Old SSID", "old-password"));
    FakeFlash.eraseByteBudget = 0;
    assert(Access::saveCredentials(portal, "New SSID", "new-password"));
    FakeFlash.eraseByteBudget = -1;
    assert(!slotBlank(0));
    assert(slotSequence(0) == 1);
    assert(slotSequence(1) == 2);
  }
  resetFakeRuntime(true);
  expectLoaded("New SSID", "new-password");

  // One torn slot and one blank slot is damage, not an empty store.
  makeTornFirstWrite();
  expectCorruptRecordRejected();
  resetFakeRuntime(true);
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(!portal.hasSavedCredentials());
    assert(Access::credentialStatus(portal) == CredentialStatus::Corrupt);
    assert(Access::saveCredentials(portal, "Recovered SSID", "recovered-pass"));
  }
  resetFakeRuntime(true);
  expectLoaded("Recovered SSID", "recovered-pass");

  // Erasing a torn single slot scrubs it and leaves nothing loadable.
  makeTornFirstWrite();
  resetFakeRuntime(true);
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(portal.eraseCredentials(false));
    assert(slotBlank(0));
    assert(slotBlank(1));
    assert(Access::credentialStatus(portal) == CredentialStatus::NotFound);
  }
  resetFakeRuntime(true);
  expectNoCredentials(CredentialStatus::NotFound);

  // --- Alternating slots and sequence numbers -------------------------------
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    for (uint32_t round = 1; round <= 4; ++round) {
      const size_t index = (round - 1) % 2;
      const std::string ssid = "Round " + std::to_string(round);
      const std::string password = "round-password-" + std::to_string(round);
      const uint32_t safeBefore = FakeFlash.safeExecuteCalls;
      assert(Access::saveCredentials(portal, ssid, password));
      // The first save only writes. Later saves write, then erase the old slot.
      assert(FakeFlash.safeExecuteCalls - safeBefore == (round == 1 ? 1u : 2u));
      assert(slotSequence(index) == round);
      assert(slotKind(index) == Access::slotKindCredential());
      assert(slotBlank(1 - index));
    }
  }
  resetFakeRuntime(true);
  expectLoaded("Round 4", "round-password-4");

  // --- Sequence wrap-around -------------------------------------------------
  const std::vector<uint8_t> beforeWrap = makeRecord("Before wrap", "before-password");
  const std::vector<uint8_t> afterWrap = makeRecord("After wrap", "after-password");

  // Slot 1 holds sequence 0, which is newer than 0xFFFFFFFF.
  resetFakeRuntime();
  writeRawSlot(0, 0xFFFFFFFFUL, Access::slotKindCredential(), beforeWrap.data());
  writeRawSlot(1, 0, Access::slotKindCredential(), afterWrap.data());
  resetFakeRuntime(true);
  expectLoaded("After wrap", "after-password");

  // Same pair with the slots swapped.
  resetFakeRuntime();
  writeRawSlot(0, 0, Access::slotKindCredential(), afterWrap.data());
  writeRawSlot(1, 0xFFFFFFFFUL, Access::slotKindCredential(), beforeWrap.data());
  resetFakeRuntime(true);
  expectLoaded("After wrap", "after-password");

  // A save after the wrap targets the non-newest slot with sequence 1.
  resetFakeRuntime();
  writeRawSlot(0, 0xFFFFFFFFUL, Access::slotKindCredential(), beforeWrap.data());
  writeRawSlot(1, 0, Access::slotKindCredential(), afterWrap.data());
  resetFakeRuntime(true);
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Wrapped SSID", "wrapped-password"));
    assert(slotSequence(0) == 1);
    assert(slotBlank(1));
  }
  resetFakeRuntime(true);
  expectLoaded("Wrapped SSID", "wrapped-password");

  // Ordinary ordering is by sequence, not by slot index.
  resetFakeRuntime();
  writeRawSlot(0, 6, Access::slotKindCredential(), afterWrap.data());
  writeRawSlot(1, 5, Access::slotKindCredential(), beforeWrap.data());
  resetFakeRuntime(true);
  expectLoaded("After wrap", "after-password");

  // --- Erase ----------------------------------------------------------------
  // The tombstone is committed to the other slot before the credential is
  // scrubbed. Two safe executes: tombstone, then scrub.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Erase SSID", "erase-password"));
    const uint32_t safeBefore = FakeFlash.safeExecuteCalls;
    assert(portal.eraseCredentials(false));
    assert(FakeFlash.safeExecuteCalls - safeBefore == 2);
    assert(slotKind(1) == Access::slotKindErased());
    assert(slotSequence(1) == 2);
    assert(slotBlank(0));
    assert(portal.lastError().empty());
    assert(Access::credentialStatus(portal) == CredentialStatus::NotFound);
  }
  resetFakeRuntime(true);
  expectNoCredentials(CredentialStatus::NotFound);

  // If the tombstone cannot be committed, nothing is scrubbed and the cache is
  // left Unknown so the next access reloads from flash.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Erase SSID", "erase-password"));
    FakeFlash.failSafeExecute = 1;
    const uint32_t safeBefore = FakeFlash.safeExecuteCalls;
    assert(!portal.eraseCredentials(false));
    assert(FakeFlash.safeExecuteCalls - safeBefore == 1);
    assert(!slotBlank(0));
    assert(slotBlank(1));
    assert(portal.lastError() == "Unable to commit the credential erase");
    assert(Access::credentialStatus(portal) == CredentialStatus::Unknown);
    assert(portal.hasSavedCredentials());
    assert(Access::savedPassword(portal) == "erase-password");
  }
  resetFakeRuntime(true);
  expectLoaded("Erase SSID", "erase-password");

  // Power loss after the tombstone but before the scrub: Incomplete, and the
  // reboot reports NotFound. The old record is still in flash but never loads.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Erase SSID", "erase-password"));
    FakeFlash.eraseByteBudget = 0;
    assert(!portal.eraseCredentials(false));
    FakeFlash.eraseByteBudget = -1;
    assert(portal.lastError() ==
           "Credential erase is incomplete; the erase marker prevents recovery");
    assert(Access::credentialStatus(portal) == CredentialStatus::NotFound);
    assert(slotKind(1) == Access::slotKindErased());
    assert(!slotBlank(0));
  }
  resetFakeRuntime(true);
  expectNoCredentials(CredentialStatus::NotFound);
  {
    // A later save supersedes the stale record and the tombstone.
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Next SSID", "next-password"));
    assert(slotSequence(0) == 3);
    assert(slotBlank(1));
  }
  resetFakeRuntime(true);
  expectLoaded("Next SSID", "next-password");

  // An erase over a torn second slot scrubs the torn bytes.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Stable SSID", "stable-password"));
    FakeFlash.programByteBudget = 40;
    assert(!Access::saveCredentials(portal, "Torn SSID", "torn-password"));
    FakeFlash.programByteBudget = -1;
    assert(!slotBlank(1));
    assert(portal.eraseCredentials(false));
    assert(slotBlank(0));
    assert(slotKind(1) == Access::slotKindErased());
    assert(slotSequence(1) == 2);
  }
  resetFakeRuntime(true);
  expectNoCredentials(CredentialStatus::NotFound);

  // --- Disconnect behaviour of eraseCredentials(true) -----------------------
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Router", "router-password"));
    assert(portal.eraseCredentials(true));
    assert(FakeCyw43.leaveCalls == 1);
    assert(portal.state() == State::Idle);
    assert(portal.lastError().empty());
    assert(Access::credentialStatus(portal) == CredentialStatus::NotFound);
  }
  resetFakeRuntime(true);
  expectNoCredentials(CredentialStatus::NotFound);

  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Router", "router-password"));
    fakeLinkUp();
    assert(portal.eraseCredentials(true));
    assert(FakeCyw43.leaveCalls == 1);
    assert(FakeCyw43.linkStatus == CYW43_LINK_DOWN);
    assert(portal.state() == State::Idle);
  }

  // The credentials are erased even when the disconnect fails. The caller
  // still gets false and a precise error.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Router", "router-password"));
    fakeLinkUp();
    FakeCyw43.leaveResult = -1;
    assert(!portal.eraseCredentials(true));
    assert(portal.lastError() ==
           "Credentials erased, but the STA interface did not disconnect");
    assert(portal.state() == State::Failed);
    assert(FakeCyw43.leaveCalls == 1);
  }
  resetFakeRuntime(true);
  expectNoCredentials(CredentialStatus::NotFound);

  // --- Wipe of cached credentials -------------------------------------------
  // The cache's buffer stays allocated after clear(), so the bytes that were
  // held can be inspected through a reference taken before the wipe.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, repeated('S', 32), repeated('P', 63)));
    assert(portal.hasSavedCredentials());
    const std::string& cached = Access::savedPassword(portal);
    const char* bytes = cached.data();
    const size_t length = cached.size();
    assert(length == 63);
    assert(portal.eraseCredentials(false));
    for (size_t i = 0; i < length; ++i) assert(bytes[i] == '\0');
  }

  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(Access::saveCredentials(portal, "Wipe SSID", repeated('P', 63)));
    assert(portal.hasSavedCredentials());
    const std::string& cached = Access::savedPassword(portal);
    const char* bytes = cached.data();
    const size_t length = cached.size();
    FakeFlash.failSafeExecute = 1;
    assert(!portal.eraseCredentials(false));
    for (size_t i = 0; i < length; ++i) assert(bytes[i] == '\0');
  }

  std::cout << "Credential slot, power-loss, wrap and erase tests passed\n";
  return 0;
}

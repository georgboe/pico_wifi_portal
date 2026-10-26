#include "host/FakePico.h"
#include "host/TestAccess.h"

#include "host/TestAssert.h"
#include <cstdint>
#include <iostream>
#include <string>

namespace {

using Access = PicoWiFiPortalTestAccess;
using CredentialStatus = Access::CredentialStatus;
using State = PicoWiFiPortal::State;

// The fake program image ends at 0x10000 and this build places the credential
// region at 0x8000, so every flash operation must be refused.
void expectNoFlashAccess() {
  assert(FakeFlash.eraseCalls == 0);
  assert(FakeFlash.programCalls == 0);
  assert(FakeFlash.safeExecuteCalls == 0);
}

}  // namespace

int main() {
  resetFakeRuntime();
  assert(Access::slotOffset(0) == 0x8000);
  assert(!Access::Store::regionUsable());

  {
    PicoWiFiPortal portal;
    portal.setLogging(false);

    assert(!portal.hasSavedCredentials());
    assert(Access::credentialStatus(portal) == CredentialStatus::Unavailable);
    assert(portal.savedSSID().empty());
    assert(Access::savedPassword(portal).empty());

    assert(!Access::saveCredentials(portal, "Valid SSID", "valid-password"));
    assert(portal.lastError() ==
           "Unable to commit the Wi-Fi credential transaction");
    assert(Access::credentialStatus(portal) == CredentialStatus::Unavailable);

    assert(!portal.eraseCredentials(false));
    assert(portal.lastError() == "Unable to commit the credential erase");
    assert(Access::credentialStatus(portal) == CredentialStatus::Unknown);

    assert(!portal.connectSaved(1000));
    assert(portal.state() == State::Failed);
    assert(portal.lastError() ==
           "Credential flash region is unusable; check PICO_WIFI_PORTAL_FLASH_OFFSET");
    assert(FakeCyw43.connectCalls == 0);

    portal.setAutoReconnect(true);
    FakeMillis = 1000;
    portal.process();
    assert(FakeCyw43.connectCalls == 0);
    assert(portal.state() == State::Failed);
    assert(portal.lastError() ==
           "Auto reconnect rejected an unusable credential record");
  }
  expectNoFlashAccess();

  resetFakeRuntime(true);
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(!portal.hasSavedCredentials());
    assert(Access::credentialStatus(portal) == CredentialStatus::Unavailable);
  }
  expectNoFlashAccess();

  std::cout << "Credential region unusable tests passed\n";
  return 0;
}

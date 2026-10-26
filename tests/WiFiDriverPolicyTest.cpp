#include "host/FakePico.h"
#include "host/TestAccess.h"

#include "host/TestAssert.h"
#include <iostream>
#include <string>

namespace {

using DisconnectReason = PicoWiFiPortal::DisconnectReason;
using IPv4 = PicoWiFiPortal::IPv4Address;
using State = PicoWiFiPortal::State;

const char kOwnerMessage[] =
    "Wi-Fi is already managed by another PicoWiFiPortal instance";
const char kCandidateBody[] =
    "ssid=Candidate%20Router&password=candidate-password";

void expectStopped(const PicoWiFiPortal& portal) {
  assert(!portal.isPortalActive());
  assert(!FakeCyw43.apEnabled);
  assert(fakeTcpListener(80) == nullptr);
  assert(fakeUdpPcb(53) == nullptr);
  assert(fakeUdpPcb(67) == nullptr);
}

void submitCandidate(PicoWiFiPortal& portal) {
  const FakeHttpResponse response =
      httpRequest(portal, "POST", "/save", kCandidateBody);
  assert(response.status == 200);
}

// Runs the candidate from the moment it was submitted at FakeMillis == 0:
// the 350 ms pending delay, then the 20 ms settle, then connect_async().
void startCandidateConnection(PicoWiFiPortal& portal) {
  FakeMillis = 350;
  portal.process();
  FakeMillis = 370;
  portal.process();
  assert(FakeCyw43.connectCalls == 1);
}

void seedCredentials(PicoWiFiPortal& portal) {
  assert(PicoWiFiPortalTestAccess::saveCredentials(
      portal, "Reconnect Router", "reconnect-password"));
}

// Leaves the portal in an active Reconnect attempt that has called
// connect_async() and is still joining.
void beginReconnectAttempt(PicoWiFiPortal& portal) {
  portal.setAutoReconnect(true);
  FakeMillis = 1000;
  portal.process();
  FakeMillis = 1020;
  portal.process();
  assert(PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
}

}  // namespace

int main() {
  // A second instance is rejected while another owns the CYW43 driver.
  // stopConfigPortal() keeps ownership; destroying the owner releases it.
  resetFakeRuntime();
  {
    PicoWiFiPortal second;
    second.setLogging(false);
    {
      PicoWiFiPortal first;
      first.setLogging(false);
      assert(first.startConfigPortalAsync("First", "12345678"));
      assert(!second.startConfigPortalAsync("Second", "12345678"));
      assert(second.lastError() == kOwnerMessage);
      assert(second.state() == State::Failed);
      assert(FakeCyw43.apEnableCalls == 1);
      first.stopConfigPortal();

      assert(!second.startConfigPortalAsync("Second", "12345678"));
      assert(second.lastError() == kOwnerMessage);
      assert(FakeCyw43.apEnableCalls == 1);
    }
    assert(second.startConfigPortalAsync("Second", "12345678"));
    second.stopConfigPortal();
    expectStopped(second);
  }

  // A non-owner setAutoReconnect(false) changes nothing. Once the owner is
  // gone, the same call succeeds.
  resetFakeRuntime();
  {
    PicoWiFiPortal second;
    second.setLogging(false);
    {
      PicoWiFiPortal first;
      first.setLogging(false);
      assert(first.startConfigPortalAsync("Owner", "12345678"));

      const uint32_t leaveCalls = FakeCyw43.leaveCalls;
      const uint32_t staEnableCalls = FakeCyw43.staEnableCalls;
      const int linkStatus = FakeCyw43.linkStatus;
      second.setAutoReconnect(false);

      assert(second.autoReconnectEnabled());
      assert(second.lastError() == kOwnerMessage);
      assert(FakeCyw43.leaveCalls == leaveCalls);
      assert(FakeCyw43.staEnableCalls == staEnableCalls);
      assert(FakeCyw43.linkStatus == linkStatus);
      first.stopConfigPortal();
    }

    second.setAutoReconnect(false);
    assert(!second.autoReconnectEnabled());
    assert(second.lastError().empty());
  }

  // A non-owner eraseCredentials(true) erases flash but leaves Wi-Fi alone.
  resetFakeRuntime();
  {
    PicoWiFiPortal second;
    second.setLogging(false);
    {
      PicoWiFiPortal first;
      first.setLogging(false);
      assert(PicoWiFiPortalTestAccess::saveCredentials(
          first, "Stored Router", "stored-password"));
      assert(first.startConfigPortalAsync("Owner-Erase", "12345678"));
      fakeLinkUp();

      const uint32_t leaveCalls = FakeCyw43.leaveCalls;
      const uint32_t apDisableCalls = FakeCyw43.apDisableCalls;
      const uint32_t staEnableCalls = FakeCyw43.staEnableCalls;
      assert(!second.eraseCredentials(true));
      assert(second.lastError() ==
             "Credentials erased, but Wi-Fi disconnect requires ownership");
      assert(FakeCyw43.leaveCalls == leaveCalls);
      assert(FakeCyw43.apDisableCalls == apDisableCalls);
      assert(FakeCyw43.staEnableCalls == staEnableCalls);
      assert(FakeCyw43.linkStatus == CYW43_LINK_UP);
      assert(first.isPortalActive());
      first.stopConfigPortal();
    }

    PicoWiFiPortal probe;
    probe.setLogging(false);
    assert(!probe.hasSavedCredentials());
  }

  // Hostname: at most 63 bytes, applied to the STA netif before the first
  // Wi-Fi operation, rejected afterwards.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(!portal.setHostname(std::string(64, 'h').c_str()));
    assert(portal.lastError() == "Hostname must contain at most 63 bytes");
    assert(portal.setHostname(std::string(63, 'h').c_str()));
    assert(portal.setHostname("ewp-device"));
    assert(portal.startConfigPortalAsync("Hostname", "12345678"));
    assert(fakeStaNetif()->hostname != nullptr);
    assert(std::string(fakeStaNetif()->hostname) == "ewp-device");

    assert(!portal.setHostname("too-late"));
    assert(portal.lastError() ==
           "Hostname must be configured before the first Wi-Fi operation");
    portal.stopConfigPortal();
    expectStopped(portal);
  }

  // A failed leave while cancelling a Reconnect keeps the STA link up: the
  // state stays Connected and the failure is reported.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    beginReconnectAttempt(portal);

    fakeLinkUp();
    FakeCyw43.leaveResult = -1;
    portal.setAutoReconnect(false);
    assert(!portal.autoReconnectEnabled());
    assert(portal.state() == State::Connected);
    assert(portal.isConnected());
    assert(portal.lastError() == "Failed to cancel the STA connection attempt");
  }

  // The AP SSID is checked before any driver call.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(!portal.startConfigPortalAsync(std::string(33, 'A').c_str(),
                                          "12345678"));
    assert(portal.lastError() == "AP SSID must contain 1-32 bytes");
    assert(FakeCyw43.staEnableCalls == 0);
    assert(FakeCyw43.apEnableCalls == 0);
  }

  // Without cyw43_arch_init() nothing starts, and a later init lets the same
  // instance start normally.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    FakeCyw43.initialized = false;
    assert(!portal.startConfigPortalAsync("Uninitialized", "12345678"));
    assert(portal.lastError() ==
           "cyw43_arch_init() must be called before using PicoWiFiPortal");
    assert(portal.state() == State::Failed);
    assert(FakeCyw43.staEnableCalls == 0);
    assert(FakeCyw43.apEnableCalls == 0);

    FakeCyw43.initialized = true;
    assert(portal.startConfigPortalAsync("Initialized", "12345678"));
    portal.stopConfigPortal();
    expectStopped(portal);
  }

  // The 32-byte SoftAP SSID limit is inclusive.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(portal.startConfigPortalAsync(std::string(32, 'A').c_str(),
                                         "12345678"));
    assert(FakeCyw43.apSSID == std::string(32, 'A'));
    portal.stopConfigPortal();
    expectStopped(portal);
  }

  // Static STA IP is applied on the next attempt: netif address, gateway,
  // DNS servers, and DHCP stopped. Restoring DHCP zeroes the address and
  // starts DHCP again.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_UP;
    assert(portal.setSTAStaticIP(IPv4(192, 168, 50, 20), IPv4(192, 168, 50, 1),
                                 IPv4(255, 255, 255, 0), IPv4(1, 1, 1, 1),
                                 IPv4(8, 8, 8, 8)));
    assert(portal.isSTAStaticIPConfigured());
    assert(portal.connectSaved(1000));

    assert(fakeAddress(&fakeStaNetif()->ip_addr) == IPv4(192, 168, 50, 20));
    assert(fakeAddress(&fakeStaNetif()->netmask) == IPv4(255, 255, 255, 0));
    assert(fakeAddress(&fakeStaNetif()->gw) == IPv4(192, 168, 50, 1));
    assert(fakeAddress(&FakeLwip.dnsServers[0]) == IPv4(1, 1, 1, 1));
    assert(fakeAddress(&FakeLwip.dnsServers[1]) == IPv4(8, 8, 8, 8));
    assert(FakeLwip.dhcpStopCalls == 1);
    assert(FakeLwip.dhcpStartCalls == 0);
    assert(!fakeStaNetif()->dhcpStarted);
    assert(portal.localIP() == IPv4(192, 168, 50, 20));

    portal.useSTADHCP();
    assert(!portal.isSTAStaticIPConfigured());
    assert(portal.connectSaved(1000));
    assert(fakeStaNetif()->ip_addr.addr == 0);
    assert(fakeStaNetif()->dhcpStarted);
    assert(FakeLwip.dhcpStartCalls == 1);
    assert(FakeLwip.dhcpStopCalls == 1);
    assert(FakeCyw43.connectCalls == 2);
  }

  // connect_async() failure ends the blocking attempt with a clear error.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    portal.setAutoReconnect(false);
    FakeCyw43.connectResult = -1;
    assert(!portal.connectSaved(1000));
    assert(portal.lastError() == "Unable to start Wi-Fi connection");
    assert(FakeCyw43.connectCalls == 1);
    assert(portal.state() == State::Failed);
  }

  // An open network is joined with a null password.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(PicoWiFiPortalTestAccess::saveCredentials(portal, "Open Router", ""));
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_UP;
    assert(portal.connectSaved(1000));
    assert(FakeCyw43.lastSSID == "Open Router");
    assert(FakeCyw43.lastPasswordNull);
    assert(FakeCyw43.lastPassword.empty());
  }

  // A failed disconnect while already connected stops connectSaved().
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    fakeLinkUp();
    FakeCyw43.leaveResult = -1;
    assert(!portal.connectSaved(1000));
    assert(portal.lastError() == "Failed to disconnect the current STA connection");
    assert(FakeCyw43.connectCalls == 0);
    assert(portal.state() == State::Failed);
  }

  // Portal candidate with a bad password: a terminal authentication failure
  // reports AuthFailed and leaves the portal running for another try.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(portal.startConfigPortalAsync("Auth-Failure", "12345678"));
    submitCandidate(portal);
    startCandidateConnection(portal);

    FakeCyw43.linkStatus = CYW43_LINK_BADAUTH;
    portal.process();
    assert(portal.state() == State::Portal);
    assert(portal.lastDisconnectReason() == DisconnectReason::AuthFailed);
    assert(portal.lastError().find("authentication failed") !=
           std::string::npos);
    assert(!portal.isPortalConnectionAttemptActive());
    assert(portal.isPortalActive());
    assert(!portal.hasSavedCredentials());
    portal.stopConfigPortal();
    expectStopped(portal);
  }

  // Portal candidate retries follow the retry policy: 1 + 2 retries, with
  // the retry delays 1000 ms and 2000 ms, then a terminal "unable" error.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(portal.startConfigPortalAsync("Retry-Policy", "12345678"));
    assert(portal.setConnectionRetryPolicy(2, 1000, 60000));
    submitCandidate(portal);
    startCandidateConnection(portal);

    FakeCyw43.linkStatus = CYW43_LINK_NONET;
    portal.process();
    assert(PicoWiFiPortalTestAccess::portalRetriesUsed(portal) == 1);
    assert(PicoWiFiPortalTestAccess::connectPending(portal));
    assert(portal.isPortalConnectionAttemptActive());
    assert(portal.state() == State::Portal);

    FakeMillis = 1369;
    portal.process();
    assert(FakeCyw43.connectCalls == 1);
    FakeMillis = 1370;
    portal.process();
    assert(FakeCyw43.connectCalls == 1);
    portal.process();
    assert(FakeCyw43.connectCalls == 2);

    FakeCyw43.linkStatus = CYW43_LINK_NONET;
    portal.process();
    assert(PicoWiFiPortalTestAccess::portalRetriesUsed(portal) == 2);

    FakeMillis = 3369;
    portal.process();
    assert(FakeCyw43.connectCalls == 2);
    FakeMillis = 3370;
    portal.process();
    portal.process();
    assert(FakeCyw43.connectCalls == 3);

    FakeCyw43.linkStatus = CYW43_LINK_NONET;
    portal.process();
    assert(!PicoWiFiPortalTestAccess::connectPending(portal));
    assert(!portal.isPortalConnectionAttemptActive());
    assert(portal.state() == State::Portal);
    assert(portal.lastError() ==
           "Unable to connect. Check the SSID/password and try again.");
    assert(portal.lastDisconnectReason() == DisconnectReason::NetworkNotFound);
    assert(FakeCyw43.connectCalls == 3);
    portal.stopConfigPortal();
    expectStopped(portal);
  }

  // A successful candidate saves the credentials, fires both callbacks and
  // stops the portal. A fresh instance can load the saved credentials.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    int savedCallbacks = 0;
    int connectedCallbacks = 0;
    portal.onCredentialsSaved([&savedCallbacks]() { ++savedCallbacks; });
    portal.onConnected([&connectedCallbacks]() { ++connectedCallbacks; });
    assert(portal.startConfigPortalAsync("Candidate", "12345678"));
    submitCandidate(portal);
    startCandidateConnection(portal);

    fakeLinkUp();
    portal.process();
    assert(savedCallbacks == 1);
    assert(connectedCallbacks == 1);
    assert(portal.state() == State::Connected);
    assert(portal.isConnected());
    assert(!portal.isPortalActive());
    assert(portal.savedSSID() == "Candidate Router");
    assert(PicoWiFiPortalTestAccess::savedPassword(portal) ==
           "candidate-password");
    expectStopped(portal);

    PicoWiFiPortal probe;
    probe.setLogging(false);
    assert(probe.hasSavedCredentials());
    assert(probe.savedSSID() == "Candidate Router");
  }

  // Bug 2: another instance erasing the shared credentials must stop the
  // owner's auto reconnect from reusing its cached copy.
  resetFakeRuntime();
  {
    PicoWiFiPortal owner;
    owner.setLogging(false);
    PicoWiFiPortal other;
    other.setLogging(false);
    seedCredentials(owner);
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_UP;
    assert(owner.connectSaved(15000));
    owner.process();
    assert(owner.state() == State::Connected);

    // Not the owner: the flash record is erased, Wi-Fi is left alone.
    assert(!other.eraseCredentials(true));
    assert(other.lastError() ==
           "Credentials erased, but Wi-Fi disconnect requires ownership");

    const uint32_t connectCalls = FakeCyw43.connectCalls;
    FakeCyw43.linkStatus = CYW43_LINK_DOWN;
    owner.process();
    assert(owner.lastDisconnectReason() == DisconnectReason::LinkLost);
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(owner));

    FakeMillis += PicoWiFiPortalTestAccess::reconnectDelay(owner);
    owner.process();
    assert(FakeCyw43.connectCalls == connectCalls);
    assert(owner.state() == State::Failed);
    assert(owner.lastError() ==
           "Auto reconnect requires saved Wi-Fi credentials");
    assert(!PicoWiFiPortalTestAccess::reconnectScheduled(owner));
    assert(!owner.hasSavedCredentials());
  }

  // Bug 2: a reconnect still settling when the credentials are erased must
  // fail without calling connect_async() with the old SSID and password.
  resetFakeRuntime();
  {
    PicoWiFiPortal owner;
    owner.setLogging(false);
    PicoWiFiPortal other;
    other.setLogging(false);
    seedCredentials(owner);
    owner.setAutoReconnect(true);
    FakeMillis = 1000;
    owner.process();
    assert(PicoWiFiPortalTestAccess::reconnectAttemptActive(owner));
    assert(FakeCyw43.connectCalls == 0);

    assert(other.eraseCredentials(false));
    FakeMillis = 1020;
    owner.process();
    assert(FakeCyw43.connectCalls == 0);
    assert(!PicoWiFiPortalTestAccess::connectAttemptActive(owner));
    assert(owner.lastError() == "Wi-Fi credentials are unavailable");

    FakeMillis += PicoWiFiPortalTestAccess::reconnectDelay(owner);
    owner.process();
    assert(FakeCyw43.connectCalls == 0);
    assert(owner.state() == State::Failed);
    assert(owner.lastError() ==
           "Auto reconnect requires saved Wi-Fi credentials");
  }

  // Bug 2: a credential save by another instance replaces the owner's cache.
  resetFakeRuntime();
  {
    PicoWiFiPortal owner;
    owner.setLogging(false);
    PicoWiFiPortal other;
    other.setLogging(false);
    seedCredentials(owner);
    assert(owner.savedSSID() == "Reconnect Router");

    assert(PicoWiFiPortalTestAccess::saveCredentials(
        other, "Other Router", "other-password"));
    assert(owner.savedSSID() == "Other Router");
    assert(owner.hasSavedCredentials());
  }

  std::cout << "Wi-Fi driver ownership, hostname, link and portal candidate policy tests passed\n";
  return 0;
}

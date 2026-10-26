#include "host/FakePico.h"
#include "host/TestAccess.h"

#include "PortalPage.h"
#include "host/TestAssert.h"
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

using Access = PicoWiFiPortalTestAccess;
using Address = PicoWiFiPortal::IPv4Address;
using State = PicoWiFiPortal::State;

constexpr const char* kPortalRedirect = "http://192.168.4.1/";

void expectContains(const std::string& value, const char* expected) {
  assert(value.find(expected) != std::string::npos);
}

void expectNotContains(const std::string& value, const char* unexpected) {
  assert(value.find(unexpected) == std::string::npos);
}

std::string header(const FakeHttpResponse& response, const char* name) {
  const auto found = response.headers.find(name);
  return found == response.headers.end() ? std::string() : found->second;
}

// Every portal reply is complete and self-describing, and the server closes
// the connection once the response is queued.
void expectClosedResponse(const FakeHttpResponse& response, int status) {
  assert(response.status == status);
  assert(response.closed);
  assert(header(response, "Connection") == "close");
  assert(header(response, "Content-Length") ==
         std::to_string(response.body.size()));
}

void expectRedirect(const FakeHttpResponse& response, const char* location) {
  expectClosedResponse(response, 302);
  assert(header(response, "Location") == location);
}

// Everything the portal allocated or bound must be gone, and the default
// route must point back at STA.
void expectFullyStopped(const PicoWiFiPortal& portal) {
  assert(!portal.isPortalActive());
  assert(!FakeCyw43.apEnabled);
  assert(fakeUdpPcb(53) == nullptr);  // DNS
  assert(fakeUdpPcb(67) == nullptr);  // DHCP
  assert(fakeTcpListener(80) == nullptr);
  for (const tcp_pcb& pcb : FakeLwip.tcpPcbs) {
    assert(pcb.localPort != 80 ||
           (pcb.state != FakeTcpState::Active &&
            pcb.state != FakeTcpState::Listening));
  }
  assert(!Access::servicesAllocated(portal));
  assert(FakeLwip.lockDepth == 0);
  assert(FakeLwip.livePbufs == 0);
  assert(FakeLwip.defaultNetif == fakeStaNetif());
}

// Runs process() and reports whether it asked the watchdog to reboot.
bool processRequestsReboot(PicoWiFiPortal& portal) {
  try {
    portal.process();
  } catch (const FakeReboot&) {
    return true;
  }
  return false;
}

struct DnsReply {
  uint8_t rcode;
  uint16_t answers;
  Address address;  // Valid only when answers == 1.
};

// Minimal A/AAAA query for "portal." with transaction ID 0x1234 and RD set.
std::vector<uint8_t> dnsQuery(uint8_t type) {
  return {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          6,    'p',  'o',  'r',  't',  'a',  'l',  0x00,
          0x00, type, 0x00, 0x01};
}

// Delivers a query to the DNS server on port 53 and decodes the single reply.
DnsReply askDNS(uint8_t type) {
  const std::vector<uint8_t> query = dnsQuery(type);
  const size_t sentBefore = FakeLwip.udpSent.size();
  assert(fakeUdpDeliver(53, query));
  assert(FakeLwip.udpSent.size() == sentBefore + 1);
  const std::vector<uint8_t>& reply = FakeLwip.udpSent.back().data;
  assert(reply.size() >= query.size());
  assert(reply[0] == query[0] && reply[1] == query[1]);
  assert((reply[2] & 0x80) != 0);  // Response bit.

  DnsReply result{static_cast<uint8_t>(reply[3] & 0x0F),
                  static_cast<uint16_t>((reply[6] << 8) | reply[7]),
                  Address()};
  if (result.answers == 1) {
    // Answer record: name pointer, type, class, TTL, RDLENGTH, RDATA.
    assert(reply.size() == query.size() + 16);
    const uint8_t* rdata = reply.data() + query.size() + 12;
    result.address = Address(rdata[0], rdata[1], rdata[2], rdata[3]);
  }
  return result;
}

// Copies the whole credential A/B slot area out of fake flash.
std::vector<uint8_t> credentialFlashSnapshot() {
  const uint32_t begin = Access::slotOffset(0);
  const uint32_t end = Access::slotOffset(1) +
                       static_cast<uint32_t>(Access::slotSize());
  const uint8_t* first = fakeFlashAt(begin);
  return std::vector<uint8_t>(first, first + (end - begin));
}

void expectStartFailure(PicoWiFiPortal& portal, const char* message) {
  assert(!portal.startConfigPortalAsync("Failure-Portal", nullptr, 0));
  assert(portal.lastError() == message);
  assert(portal.state() == State::Failed);
  expectFullyStopped(portal);
}

void expectRejectedStart(PicoWiFiPortal& portal,
                         const char* ssid,
                         const char* password,
                         const char* message) {
  const uint32_t enableCallsBefore = FakeCyw43.apEnableCalls;
  assert(!portal.startConfigPortalAsync(ssid, password, 0));
  assert(portal.lastError() == message);
  assert(FakeCyw43.apEnableCalls == enableCallsBefore);
  assert(!FakeCyw43.apEnabled);
  assert(!portal.isPortalActive());
  assert(!Access::servicesAllocated(portal));
}

void testDefaultsAndRoutes() {
  PicoWiFiPortal portal;
  portal.setLogging(false);

  assert(portal.portalIP() == Address(192, 168, 4, 1));
  assert(portal.startConfigPortalAsync("Default-Portal", nullptr, 0));
  assert(portal.isPortalActive());
  assert(portal.state() == State::Portal);
  assert(FakeCyw43.apEnabled);
  assert(FakeCyw43.apSSID == "Default-Portal");
  assert(FakeCyw43.apPasswordNull);
  assert(FakeCyw43.apAuth == CYW43_AUTH_WPA2_AES_PSK);
  assert(FakeCyw43.apChannel == 1);
  assert(fakeAddress(&fakeApNetif()->ip_addr) == Address(192, 168, 4, 1));
  assert(fakeAddress(&fakeApNetif()->netmask) == Address(255, 255, 255, 0));
  assert(fakeAddress(&fakeApNetif()->gw) == Address(192, 168, 4, 1));
  assert(FakeLwip.defaultNetif == fakeStaNetif());
  assert(fakeUdpPcb(53) != nullptr);
  assert(fakeUdpPcb(67) != nullptr);
  assert(fakeTcpListener(80) != nullptr);
  assert(Access::redirectURL(portal) == kPortalRedirect);

  // Every A query gets the portal address; other types get an empty answer.
  const DnsReply a = askDNS(1);
  assert(a.rcode == 0 && a.answers == 1);
  assert(a.address == Address(192, 168, 4, 1));
  const DnsReply aaaa = askDNS(28);
  assert(aaaa.rcode == 0 && aaaa.answers == 0);

  FakeHttpResponse root = httpRequest(portal, "GET", "/");
  expectClosedResponse(root, 200);
  assert(header(root, "Content-Type") == "text/html; charset=utf-8");
  assert(root.body == PWP_PORTAL_HTML);
  FakeHttpResponse wifi = httpRequest(portal, "GET", "/wifi");
  expectClosedResponse(wifi, 200);
  assert(wifi.body == PWP_PORTAL_HTML);

  // Each handler accepts only its documented method. Anything else, and
  // every unknown URL, is answered with a redirect to the portal.
  expectRedirect(httpRequest(portal, "POST", "/properties"), kPortalRedirect);
  expectRedirect(httpRequest(portal, "GET", "/reset"), kPortalRedirect);
  expectRedirect(httpRequest(portal, "GET", "/save"), kPortalRedirect);
  expectRedirect(httpRequest(portal, "GET", "/unknown/page"), kPortalRedirect);
  for (const char* probe : {"/generate_204", "/gen_204", "/hotspot-detect.html",
                            "/library/test/success.html", "/connecttest.txt",
                            "/ncsi.txt", "/fwlink"}) {
    expectRedirect(httpRequest(portal, "GET", probe), kPortalRedirect);
  }

  FakeHttpResponse status = httpRequest(portal, "GET", "/status");
  expectClosedResponse(status, 200);
  assert(header(status, "Content-Type") == "application/json; charset=utf-8");
  assert(header(status, "Cache-Control") == "no-store");
  assert(status.body ==
         R"({"connected":false,"portal":true,"ip":"192.168.4.1","error":""})");

  FakeHttpResponse properties = httpRequest(portal, "GET", "/properties");
  expectClosedResponse(properties, 200);
  assert(header(properties, "Content-Type") == "application/json; charset=utf-8");
  assert(header(properties, "Cache-Control") == "no-store");
  assert(properties.body ==
         R"JSON({"ssid":"Default-Portal","softap":{"ip":"192.168.4.1","gateway":"192.168.4.1","subnet":"255.255.255.0"},"sta":{"connected":false,"ip":"","gateway":"","subnet":""},"mac":{"ap":"28:CD:C1:00:00:01","sta":"28:CD:C1:00:00:02"},"chipId":"E6614103E7452D2F","chip":"RP2040","cpuMHz":125,"flashSize":2097152,"freeHeap":131072})JSON");

  portal.stopConfigPortal();
  expectFullyStopped(portal);
}

void testConnectedStatusAndPendingSave() {
  PicoWiFiPortal portal;
  portal.setLogging(false);
  assert(portal.startConfigPortalAsync("Connected-Portal", nullptr, 0));

  fakeLinkUp(Address(10, 20, 30, 40), Address(10, 20, 30, 1),
             Address(255, 255, 255, 0));
  FakeHeapUsed = kFakeHeapTotal - 130048;
  FakeHttpResponse properties = httpRequest(portal, "GET", "/properties");
  expectClosedResponse(properties, 200);
  assert(properties.body ==
         R"JSON({"ssid":"Connected-Portal","softap":{"ip":"192.168.4.1","gateway":"192.168.4.1","subnet":"255.255.255.0"},"sta":{"connected":true,"ip":"10.20.30.40","gateway":"10.20.30.1","subnet":"255.255.255.0"},"mac":{"ap":"28:CD:C1:00:00:01","sta":"28:CD:C1:00:00:02"},"chipId":"E6614103E7452D2F","chip":"RP2040","cpuMHz":125,"flashSize":2097152,"freeHeap":130048})JSON");
  FakeHeapUsed = 131072;

  FakeHttpResponse connected = httpRequest(portal, "GET", "/status");
  assert(connected.body ==
         R"({"connected":true,"portal":true,"ip":"10.20.30.40","error":""})");

  // A pending Portal candidate is not reported as connected, and its
  // credentials never appear in /properties.
  FakeHttpResponse save = httpRequest(portal, "POST", "/save",
                                      "ssid=Pending%20Router&password=pending-password");
  expectClosedResponse(save, 200);
  assert(save.body == PWP_CONNECTING_HTML);
  assert(Access::connectPending(portal));
  assert(portal.isPortalConnectionAttemptActive());
  assert(Access::pendingSSID(portal) == "Pending Router");
  assert(Access::pendingPassword(portal) == "pending-password");

  FakeHttpResponse pendingStatus = httpRequest(portal, "GET", "/status");
  expectContains(pendingStatus.body, "\"connected\":false");

  FakeHttpResponse afterSave = httpRequest(portal, "GET", "/properties");
  expectNotContains(afterSave.body, "Pending Router");
  expectNotContains(afterSave.body, "pending-password");

  FakeCyw43.linkStatus = CYW43_LINK_DOWN;
  portal.stopConfigPortal();
  assert(!Access::connectPending(portal));
  expectFullyStopped(portal);
}

void testResetAndCredentialIsolation() {
  PicoWiFiPortal portal;
  portal.setLogging(false);
  FakeMillis = 100;
  assert(portal.startConfigPortalAsync("Reset-Portal", nullptr, 0));
  assert(Access::saveCredentials(portal, "Keep Router", "keep-password"));
  const std::vector<uint8_t> flashBefore = credentialFlashSnapshot();
  const uint32_t programsBefore = FakeFlash.programCalls;
  const uint32_t erasesBefore = FakeFlash.eraseCalls;
  const uint32_t rebootsBefore = FakeCyw43.rebootCalls;

  FakeHttpResponse save = httpRequest(portal, "POST", "/save",
                                      "ssid=Pending+Router&password=pending-password");
  expectClosedResponse(save, 200);
  FakeHttpResponse properties = httpRequest(portal, "GET", "/properties");
  expectNotContains(properties.body, "Keep Router");
  expectNotContains(properties.body, "keep-password");
  expectNotContains(properties.body, "Pending Router");
  expectNotContains(properties.body, "pending-password");

  // A reset is acknowledged immediately and reboots only after the delay.
  FakeHttpResponse reset = httpRequest(portal, "POST", "/reset");
  expectClosedResponse(reset, 202);
  assert(reset.body == R"({"restarting":true})");
  assert(header(reset, "Cache-Control") == "no-store");
  assert(Access::restartPending(portal));
  assert(Access::restartRequestedAt(portal) == 100);
  FakeMillis = 100 + Access::restartDelay() - 1;
  assert(!processRequestsReboot(portal));
  assert(FakeCyw43.rebootCalls == rebootsBefore);
  FakeMillis = 100 + Access::restartDelay();
  assert(processRequestsReboot(portal));
  assert(FakeCyw43.rebootCalls == rebootsBefore + 1);
  assert(!Access::restartPending(portal));

  // Reset neither erases nor rewrites the credential record.
  assert(credentialFlashSnapshot() == flashBefore);
  assert(FakeFlash.programCalls == programsBefore);
  assert(FakeFlash.eraseCalls == erasesBefore);
  assert(portal.hasSavedCredentials());
  assert(portal.savedSSID() == "Keep Router");
  assert(Access::savedPassword(portal) == "keep-password");

  // A fresh object, as after a real reboot, still finds the record in flash.
  {
    PicoWiFiPortal rebooted;
    rebooted.setLogging(false);
    assert(rebooted.savedSSID() == "Keep Router");
  }

  // Explicit test cleanup; the reset path above did not erase this record.
  assert(portal.eraseCredentials(false));
  assert(!portal.hasSavedCredentials());
  portal.stopConfigPortal();
  expectFullyStopped(portal);
}

void testResetWrapAndEscaping() {
  PicoWiFiPortal portal;
  portal.setLogging(false);
  FakeMillis = UINT32_MAX - 100U;
  assert(portal.startConfigPortalAsync("Reset \"Wrap\"\\Portal", nullptr, 0));

  FakeHttpResponse properties = httpRequest(portal, "GET", "/properties");
  expectContains(properties.body,
                 R"JSON("ssid":"Reset \"Wrap\"\\Portal")JSON");

  FakeMillis = UINT32_MAX - 100U;
  const uint32_t rebootsBefore = FakeCyw43.rebootCalls;
  FakeHttpResponse first = httpRequest(portal, "POST", "/reset");
  expectClosedResponse(first, 202);
  const uint32_t resetStartedAt = Access::restartRequestedAt(portal);
  assert(resetStartedAt == UINT32_MAX - 100U);

  // A repeated request keeps the first timestamp and cannot postpone reboot.
  FakeMillis += 20;
  FakeHttpResponse second = httpRequest(portal, "POST", "/reset");
  expectClosedResponse(second, 202);
  assert(Access::restartRequestedAt(portal) == resetStartedAt);

  // Unsigned millis subtraction keeps the reset timing across the wrap.
  FakeMillis = resetStartedAt + Access::restartDelay() - 1U;
  assert(!processRequestsReboot(portal));
  assert(FakeCyw43.rebootCalls == rebootsBefore);
  FakeMillis = resetStartedAt + Access::restartDelay();
  assert(processRequestsReboot(portal));
  assert(FakeCyw43.rebootCalls == rebootsBefore + 1);
  assert(!processRequestsReboot(portal));
  assert(FakeCyw43.rebootCalls == rebootsBefore + 1);
  portal.stopConfigPortal();
  expectFullyStopped(portal);
}

// Control characters in the SSID are escaped as JSON. A separate function
// keeps the previous instance alive only until it has been destroyed, since
// the library lets one object own the CYW43 driver at a time.
void testSSIDEscaping() {
  PicoWiFiPortal portal;
  portal.setLogging(false);
  assert(portal.startConfigPortalAsync("Ctl\x01" "Tab\t", nullptr, 0));
  FakeHttpResponse properties = httpRequest(portal, "GET", "/properties");
  expectContains(properties.body, R"JSON("ssid":"Ctl\u0001Tab\t")JSON");
  portal.stopConfigPortal();
  expectFullyStopped(portal);
}

void testCustomAddressCycles() {
  PicoWiFiPortal portal;
  portal.setLogging(false);
  assert(portal.setPortalIP(Address(200, 5, 29, 8)));
  assert(portal.portalIP() == Address(200, 5, 29, 8));

  for (int cycle = 0; cycle < 500; ++cycle) {
    assert(portal.startConfigPortalAsync("Custom-Portal", "12345678", 0));
    assert(portal.isPortalActive());
    assert(portal.state() == State::Portal);
    assert(FakeCyw43.apSSID == "Custom-Portal");
    assert(!FakeCyw43.apPasswordNull && FakeCyw43.apPassword == "12345678");
    assert(FakeCyw43.apAuth == CYW43_AUTH_WPA2_AES_PSK);
    assert(fakeAddress(&fakeApNetif()->ip_addr) == Address(200, 5, 29, 8));
    assert(fakeAddress(&fakeApNetif()->netmask) == Address(255, 255, 255, 0));
    assert(fakeAddress(&fakeApNetif()->gw) == Address(200, 5, 29, 8));
    assert(FakeLwip.defaultNetif == fakeStaNetif());
    assert(Access::redirectURL(portal) == "http://200.5.29.8/");
    assert(askDNS(1).address == Address(200, 5, 29, 8));
    expectRedirect(httpRequest(portal, "GET", "/generate_204"),
                   "http://200.5.29.8/");
    portal.process();
    portal.stopConfigPortal();
    expectFullyStopped(portal);
  }

  // Rejected changes keep the previous known-good configuration intact.
  for (int attempt = 0; attempt < 500; ++attempt) {
    assert(!portal.setPortalIP(Address(200, 5, 29, 0)));
    assert(portal.portalIP() == Address(200, 5, 29, 8));
  }
  assert(portal.lastError() == "Portal IP cannot be the subnet network address");
  assert(!portal.setPortalIP(Address(200, 5, 29, 8), Address(200, 5, 30, 1),
                             Address(255, 255, 255, 0)));
  assert(portal.lastError() == "Portal IP and gateway must be in the same subnet");
  assert(portal.portalIP() == Address(200, 5, 29, 8));

  // Changes are refused while the portal runs, and the live portal is kept.
  assert(portal.startConfigPortalAsync("Custom-Portal", "12345678", 0));
  assert(!portal.setPortalIP(Address(10, 0, 0, 1)));
  assert(portal.lastError() == "Portal IP cannot be changed while the portal is active");
  assert(portal.portalIP() == Address(200, 5, 29, 8));
  assert(Access::redirectURL(portal) == "http://200.5.29.8/");
  portal.stopConfigPortal();
  expectFullyStopped(portal);
}

void testStartFailuresCleanUp() {
  PicoWiFiPortal portal;
  portal.setLogging(false);

  FakeCyw43.apStartFails = true;
  const uint32_t disablesBefore = FakeCyw43.apDisableCalls;
  expectStartFailure(portal, "Failed to start the CYW43 access point");
  assert(FakeCyw43.apDisableCalls == disablesBefore + 1);
  FakeCyw43.apStartFails = false;

  FakeLwip.apAddressOverride = true;
  FakeLwip.apAddressOverrideValue = Address(10, 9, 8, 7).toUint32();
  expectStartFailure(portal,
                     "SoftAP runtime IP/subnet does not match the portal configuration");
  FakeLwip.apAddressOverride = false;

  FakeLwip.udpBindResult = ERR_USE;
  FakeLwip.udpBindFailPort = 67;
  expectStartFailure(portal, "Failed to start captive portal DHCP");
  FakeLwip.udpBindResult = ERR_OK;
  FakeLwip.udpBindFailPort = 0;

  FakeLwip.udpNewFails = true;
  expectStartFailure(portal, "Failed to start captive portal DHCP");
  FakeLwip.udpNewFails = false;

  // DHCP is already running when the DNS bind fails; it must be torn down.
  FakeLwip.udpBindResult = ERR_USE;
  FakeLwip.udpBindFailPort = 53;
  expectStartFailure(portal, "Failed to start captive portal DNS");
  FakeLwip.udpBindResult = ERR_OK;
  FakeLwip.udpBindFailPort = 0;

  FakeLwip.tcpBindResult = ERR_USE;
  expectStartFailure(portal, "Failed to start captive portal HTTP server");
  FakeLwip.tcpBindResult = ERR_OK;

  FakeLwip.tcpListenFails = true;
  expectStartFailure(portal, "Failed to start captive portal HTTP server");
  FakeLwip.tcpListenFails = false;

  FakeLwip.tcpNewFails = true;
  expectStartFailure(portal, "Failed to start captive portal HTTP server");
  FakeLwip.tcpNewFails = false;

  assert(portal.startConfigPortalAsync("Recovered", nullptr, 0));
  assert(portal.lastError().empty());
  expectClosedResponse(httpRequest(portal, "GET", "/status"), 200);
  portal.stopConfigPortal();
  expectFullyStopped(portal);
}

void testAPCredentialValidation() {
  PicoWiFiPortal portal;
  portal.setLogging(false);
  const char* kSSIDMessage = "AP SSID must contain 1-32 bytes";
  const char* kPasswordMessage = "AP password must be empty or 8-63 characters";
  const std::string ssid32(32, 'S');
  const std::string ssid33(33, 'S');
  const std::string password63(63, 'p');
  const std::string password64(64, 'p');

  expectRejectedStart(portal, nullptr, nullptr, kSSIDMessage);
  expectRejectedStart(portal, "", nullptr, kSSIDMessage);
  expectRejectedStart(portal, ssid33.c_str(), nullptr, kSSIDMessage);
  expectRejectedStart(portal, "Valid-SSID", "1234567", kPasswordMessage);
  expectRejectedStart(portal, "Valid-SSID", password64.c_str(), kPasswordMessage);

  assert(portal.startConfigPortalAsync(ssid32.c_str(), nullptr, 0));
  assert(FakeCyw43.apSSID == ssid32);
  portal.stopConfigPortal();
  expectFullyStopped(portal);

  assert(portal.startConfigPortalAsync("Eight-Pw", "12345678", 0));
  assert(FakeCyw43.apPassword == "12345678");
  portal.stopConfigPortal();
  expectFullyStopped(portal);

  assert(portal.startConfigPortalAsync("Max-Pw", password63.c_str(), 0));
  assert(FakeCyw43.apPassword == password63);
  portal.stopConfigPortal();
  expectFullyStopped(portal);

  // An empty or null password opens the AP without a passphrase.
  // The library always passes CYW43_AUTH_WPA2_AES_PSK, even for open APs.
  assert(portal.startConfigPortalAsync("Open-Empty", "", 0));
  assert(FakeCyw43.apPasswordNull);
  portal.stopConfigPortal();
  expectFullyStopped(portal);

  assert(portal.startConfigPortalAsync("Open-Null", nullptr, 0));
  assert(FakeCyw43.apPasswordNull);
  portal.stopConfigPortal();
  expectFullyStopped(portal);
}

void testAPChannel() {
  PicoWiFiPortal portal;
  portal.setLogging(false);

  portal.setAPChannel(6);
  assert(portal.startConfigPortalAsync("Channel-Six", nullptr, 0));
  assert(FakeCyw43.apChannel == 6);
  portal.stopConfigPortal();
  expectFullyStopped(portal);

  // Out-of-range channels are ignored; the previous channel stays.
  portal.setAPChannel(0);
  portal.setAPChannel(14);
  portal.setAPChannel(200);
  assert(portal.startConfigPortalAsync("Channel-Six", nullptr, 0));
  assert(FakeCyw43.apChannel == 6);
  portal.stopConfigPortal();
  expectFullyStopped(portal);

  portal.setAPChannel(13);
  assert(portal.startConfigPortalAsync("Channel-13", nullptr, 0));
  assert(FakeCyw43.apChannel == 13);
  portal.stopConfigPortal();
  expectFullyStopped(portal);
}

void testPortalStartedCallback() {
  PicoWiFiPortal portal;
  portal.setLogging(false);
  int startedCalls = 0;
  bool portalStateInCallback = false;
  portal.onPortalStarted([&]() {
    ++startedCalls;
    portalStateInCallback =
        portal.isPortalActive() && portal.state() == State::Portal;
  });

  assert(!portal.startConfigPortalAsync("", nullptr, 0));
  assert(startedCalls == 0);

  assert(portal.startConfigPortalAsync("Callback", nullptr, 0));
  assert(startedCalls == 1);
  assert(portalStateInCallback);
  portal.stopConfigPortal();

  // A failed AP start must not announce a portal.
  FakeCyw43.apStartFails = true;
  assert(!portal.startConfigPortalAsync("Callback", nullptr, 0));
  FakeCyw43.apStartFails = false;
  assert(startedCalls == 1);

  assert(portal.startConfigPortalAsync("Callback", nullptr, 0));
  assert(startedCalls == 2);
  portal.stopConfigPortal();
  expectFullyStopped(portal);
}

void testPortalTimeouts() {
  // The deadline is measured with unsigned subtraction, so it survives the
  // 32-bit millisecond wrap.
  PicoWiFiPortal wrapped;
  wrapped.setLogging(false);
  FakeMillis = UINT32_MAX - 5U;
  assert(wrapped.startConfigPortalAsync("Wraparound", nullptr, 10));
  FakeMillis = 3;  // Nine milliseconds elapsed.
  wrapped.process();
  assert(wrapped.isPortalActive());
  FakeMillis = 4;  // Ten milliseconds elapsed.
  wrapped.process();
  assert(!wrapped.isPortalActive());
  assert(wrapped.lastError() == "Configuration portal timed out");
  assert(wrapped.state() == State::Failed);
  expectFullyStopped(wrapped);
}

void testPortalDeadlineBoundary() {
  PicoWiFiPortal plain;
  plain.setLogging(false);
  FakeMillis = 0;
  assert(plain.startConfigPortalAsync("Timeout", nullptr, 1000));
  FakeMillis = 999;
  plain.process();
  assert(plain.isPortalActive());
  FakeMillis = 1000;
  plain.process();
  assert(!plain.isPortalActive());
  assert(plain.state() == State::Failed);
  expectFullyStopped(plain);
}

}  // namespace

int main() {
  resetFakeRuntime();
  testDefaultsAndRoutes();
  testConnectedStatusAndPendingSave();
  testResetAndCredentialIsolation();
  testResetWrapAndEscaping();
  testSSIDEscaping();
  testCustomAddressCycles();
  testStartFailuresCleanUp();
  testAPCredentialValidation();
  testAPChannel();
  testPortalStartedCallback();
  testPortalTimeouts();
  testPortalDeadlineBoundary();
  assert(FakeLwip.lockDepth == 0);
  assert(FakeLwip.livePbufs == 0);

  std::cout << "Portal lifecycle, cleanup, restart and wrap tests passed\n";
  return 0;
}

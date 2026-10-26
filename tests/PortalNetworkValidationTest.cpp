#include "host/FakePico.h"
#include "host/TestAccess.h"

#include "host/TestAssert.h"
#include <iostream>
#include <string>

namespace {

using Access = PicoWiFiPortalTestAccess;
using Result = Access::Result;
using Address = PicoWiFiPortal::IPv4Address;

constexpr const char* kSTAInvalidMessage =
    "STA IP, gateway, subnet, or DNS configuration is invalid";
constexpr const char* kSTABusyMessage =
    "STA IP cannot be changed during a connection attempt";
constexpr const char* kPortalActiveMessage =
    "Portal IP cannot be changed while the portal is active";

void expect(Result expected,
            uint32_t local,
            uint32_t gateway,
            uint32_t subnet) {
  assert(Access::validate(local, gateway, subnet) == expected);
}

void expectPortalIPRejected(PicoWiFiPortal& portal,
                            const Address& local,
                            const Address& gateway,
                            const Address& subnet,
                            const char* message) {
  assert(!portal.setPortalIP(local, gateway, subnet));
  assert(portal.lastError() == message);
}

void expectSTARejected(PicoWiFiPortal& portal,
                       const Address& local,
                       const Address& gateway,
                       const Address& subnet,
                       const Address& primaryDNS = Address(),
                       const Address& secondaryDNS = Address()) {
  assert(!portal.setSTAStaticIP(local, gateway, subnet, primaryDNS,
                                secondaryDNS));
  assert(portal.lastError() == kSTAInvalidMessage);
}

}  // namespace

int main() {
  const uint32_t slash23 = Access::ipv4(255, 255, 254, 0);
  const uint32_t slash24 = Access::ipv4(255, 255, 255, 0);
  const uint32_t slash25 = Access::ipv4(255, 255, 255, 128);
  const uint32_t slash26 = Access::ipv4(255, 255, 255, 192);
  const uint32_t slash27 = Access::ipv4(255, 255, 255, 224);
  const uint32_t slash28 = Access::ipv4(255, 255, 255, 240);
  const uint32_t slash29 = Access::ipv4(255, 255, 255, 248);

  // Usable unicast range: excludes 0/8, 127/8, 224+ (multicast/reserved), and
  // the limited broadcast address.
  assert(Access::usable(Access::ipv4(10, 10, 0, 1)));
  assert(Access::usable(Access::ipv4(150, 10, 20, 1)));
  assert(Access::usable(Access::ipv4(200, 5, 29, 8)));
  assert(Access::usable(Access::ipv4(1, 0, 0, 0)));
  assert(Access::usable(Access::ipv4(223, 255, 255, 254)));
  assert(!Access::usable(Access::ipv4(0, 0, 0, 0)));
  assert(!Access::usable(Access::ipv4(0, 0, 0, 1)));
  assert(!Access::usable(Access::ipv4(127, 0, 0, 1)));
  assert(!Access::usable(Access::ipv4(224, 0, 0, 0)));
  assert(!Access::usable(Access::ipv4(224, 0, 0, 1)));
  assert(!Access::usable(Access::ipv4(255, 255, 255, 255)));

  assert(Access::contiguous(slash24));
  assert(Access::contiguous(slash25));
  assert(Access::contiguous(slash26));
  assert(Access::contiguous(slash27));
  assert(Access::contiguous(slash28));
  assert(Access::contiguous(slash29));
  assert(!Access::contiguous(Access::ipv4(255, 0, 255, 0)));
  assert(!Access::contiguous(0));
  assert(!Access::contiguous(0xFFFFFFFFUL));
  assert(Access::prefix(slash24) == 24);
  assert(Access::prefix(slash28) == 28);
  assert(Access::prefix(slash29) == 29);

  assert(Access::sameSubnet(Access::ipv4(200, 5, 29, 8),
                            Access::ipv4(200, 5, 29, 1), slash24));
  assert(!Access::sameSubnet(Access::ipv4(200, 5, 29, 8),
                             Access::ipv4(200, 5, 30, 1), slash24));
  assert(Access::network(Access::ipv4(200, 5, 29, 8), slash24) ==
         Access::ipv4(200, 5, 29, 0));
  assert(Access::broadcast(Access::ipv4(200, 5, 29, 8), slash24) ==
         Access::ipv4(200, 5, 29, 255));
  assert(Access::network(Access::ipv4(200, 5, 29, 12), slash28) ==
         Access::ipv4(200, 5, 29, 0));
  assert(Access::broadcast(Access::ipv4(200, 5, 29, 12), slash28) ==
         Access::ipv4(200, 5, 29, 15));

  // SoftAP DHCP lease start. Eleven inclusive addresses follow local + 1; an
  // overflowing range moves to network + 1.
  assert(Access::dhcpLeaseStart(Access::ipv4(200, 5, 29, 8), slash24) ==
         Access::ipv4(200, 5, 29, 9));
  assert(Access::dhcpLeaseStart(Access::ipv4(200, 5, 29, 243), slash24) ==
         Access::ipv4(200, 5, 29, 244));
  // .243 gives the pool .244-.254 (fits below broadcast). .244 would need
  // .245-.255, which hits the broadcast address, so it overflows.
  assert(Access::dhcpLeaseStart(Access::ipv4(200, 5, 29, 244), slash24) ==
         Access::ipv4(200, 5, 29, 1));
  assert(Access::dhcpLeaseStart(Access::ipv4(200, 5, 29, 254), slash24) ==
         Access::ipv4(200, 5, 29, 1));
  assert(Access::dhcpLeaseStart(Access::ipv4(200, 5, 29, 3), slash28) ==
         Access::ipv4(200, 5, 29, 4));
  assert(Access::dhcpLeaseStart(Access::ipv4(200, 5, 29, 4), slash28) ==
         Access::ipv4(200, 5, 29, 1));
  assert(Access::dhcpLeaseStart(Access::ipv4(200, 5, 29, 8), slash28) ==
         Access::ipv4(200, 5, 29, 1));

  // Required PASS matrix: legacy Class A, B, C and the RFC1918 case.
  expect(Result::Valid, Access::ipv4(10, 10, 0, 1),
         Access::ipv4(10, 10, 0, 1), slash24);
  expect(Result::Valid, Access::ipv4(150, 10, 20, 1),
         Access::ipv4(150, 10, 20, 1), slash24);
  expect(Result::Valid, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(200, 5, 29, 8), slash24);
  expect(Result::Valid, Access::ipv4(192, 168, 50, 1),
         Access::ipv4(192, 168, 50, 1), slash24);
  expect(Result::Valid, Access::ipv4(200, 5, 29, 1),
         Access::ipv4(200, 5, 29, 1), slash25);
  expect(Result::Valid, Access::ipv4(200, 5, 29, 1),
         Access::ipv4(200, 5, 29, 1), slash26);
  expect(Result::Valid, Access::ipv4(200, 5, 29, 1),
         Access::ipv4(200, 5, 29, 1), slash27);
  expect(Result::Valid, Access::ipv4(200, 5, 29, 1),
         Access::ipv4(200, 5, 29, 1), slash28);

  // Required safe failures.
  expect(Result::InvalidLocalIP, Access::ipv4(0, 0, 0, 0),
         Access::ipv4(1, 1, 1, 1), slash24);
  expect(Result::InvalidLocalIP, Access::ipv4(0, 1, 2, 3),
         Access::ipv4(0, 1, 2, 3), slash24);
  expect(Result::InvalidLocalIP, Access::ipv4(127, 0, 0, 1),
         Access::ipv4(127, 0, 0, 1), slash24);
  expect(Result::InvalidLocalIP, Access::ipv4(224, 0, 0, 1),
         Access::ipv4(224, 0, 0, 1), slash24);
  expect(Result::InvalidLocalIP, Access::ipv4(255, 255, 255, 255),
         Access::ipv4(255, 255, 255, 255), slash24);
  expect(Result::LocalIsNetworkAddress, Access::ipv4(200, 5, 29, 0),
         Access::ipv4(200, 5, 29, 1), slash24);
  expect(Result::LocalIsBroadcastAddress, Access::ipv4(200, 5, 29, 255),
         Access::ipv4(200, 5, 29, 1), slash24);
  expect(Result::DifferentSubnet, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(200, 5, 30, 1), slash24);
  expect(Result::InvalidSubnetMask, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(200, 5, 29, 8), Access::ipv4(255, 0, 255, 0));
  expect(Result::InvalidSubnetMask, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(200, 5, 29, 8), Access::ipv4(0, 0, 0, 0));
  expect(Result::InvalidSubnetMask, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(200, 5, 29, 8), Access::ipv4(255, 255, 255, 255));
  expect(Result::UnsupportedSubnet, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(200, 5, 29, 8), slash23);
  expect(Result::UnsupportedSubnet, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(200, 5, 29, 8), slash29);
  expect(Result::InvalidGateway, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(127, 0, 0, 1), slash24);
  expect(Result::GatewayIsNetworkAddress, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(200, 5, 29, 0), slash24);
  expect(Result::GatewayIsBroadcastAddress, Access::ipv4(200, 5, 29, 8),
         Access::ipv4(200, 5, 29, 255), slash24);
  expect(Result::LocalConflictsWithDHCPLease,
         Access::ipv4(200, 5, 29, 8), Access::ipv4(200, 5, 29, 8), slash28);
  expect(Result::GatewayConflictsWithDHCPLease,
         Access::ipv4(200, 5, 29, 12), Access::ipv4(200, 5, 29, 1), slash28);
  expect(Result::Valid, Access::ipv4(200, 5, 29, 12),
         Access::ipv4(200, 5, 29, 12), slash28);

  // DHCP lease pool boundaries. For a /24 with local .8 the pool is .9-.19.
  // Local .100 gives the pool .101-.111: exactly eleven addresses.
  expect(Result::Valid, Access::ipv4(200, 5, 29, 100),
         Access::ipv4(200, 5, 29, 100), slash24);
  expect(Result::GatewayConflictsWithDHCPLease, Access::ipv4(200, 5, 29, 100),
         Access::ipv4(200, 5, 29, 101), slash24);
  expect(Result::GatewayConflictsWithDHCPLease, Access::ipv4(200, 5, 29, 100),
         Access::ipv4(200, 5, 29, 111), slash24);
  expect(Result::Valid, Access::ipv4(200, 5, 29, 100),
         Access::ipv4(200, 5, 29, 112), slash24);
  // Local .254 overflows to the pool .1-.11, so a gateway at .1 conflicts.
  expect(Result::GatewayConflictsWithDHCPLease, Access::ipv4(200, 5, 29, 254),
         Access::ipv4(200, 5, 29, 1), slash24);
  expect(Result::Valid, Access::ipv4(200, 5, 29, 254),
         Access::ipv4(200, 5, 29, 12), slash24);
  // Local .2 on a /28 keeps the pool at .3-.13, so gateway .1 is free. Local .8
  // on the same /28 overflows to .1-.11 and makes gateway .1 conflict.
  expect(Result::Valid, Access::ipv4(200, 5, 29, 2),
         Access::ipv4(200, 5, 29, 1), slash28);
  expect(Result::GatewayConflictsWithDHCPLease, Access::ipv4(200, 5, 29, 3),
         Access::ipv4(200, 5, 29, 4), slash28);

  // Public Portal API uses the same validation as the helpers above.
  {
    resetFakeRuntime();
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(portal.portalIP() == Address(192, 168, 4, 1));

    assert(portal.setPortalIP(Address(10, 10, 0, 1)));
    assert(portal.portalIP() == Address(10, 10, 0, 1));
    assert(portal.setPortalIP(Address(150, 10, 20, 1)));
    assert(portal.setPortalIP(Address(200, 5, 29, 8)));
    assert(portal.setPortalIP(Address(192, 168, 50, 1)));
    assert(portal.lastError().empty());

    // Three-argument form; the one-argument overload below uses gateway = local.
    expectPortalIPRejected(portal, Address(200, 5, 29, 0),
                           Address(200, 5, 29, 0), Address(255, 255, 255, 0),
                           "Portal IP cannot be the subnet network address");
    assert(!portal.setPortalIP(Address(200, 5, 29, 0)));
    assert(!portal.setPortalIP(Address(200, 5, 29, 8), Address(200, 5, 29, 8),
                               Address(255, 255, 255, 240)));
    assert(portal.lastError() ==
           "Portal IP conflicts with the SoftAP DHCP lease range");
    // Failed setPortalIP calls leave the previous address in place.
    assert(portal.portalIP() == Address(192, 168, 50, 1));

    // Explicit Portal subnets /24.../28 are accepted.
    assert(portal.setPortalIP(Address(200, 5, 29, 12), Address(200, 5, 29, 12),
                              Address(255, 255, 255, 240)));
    assert(portal.lastError().empty());
    assert(portal.portalIP() == Address(200, 5, 29, 12));
  }

  // Each PortalNetworkValidationResult that can reach the public API reports
  // the matching lastError() message. A successful call clears it.
  {
    resetFakeRuntime();
    PicoWiFiPortal portal;
    portal.setLogging(false);
    const Address slash24Mask(255, 255, 255, 0);

    expectPortalIPRejected(portal, Address(0, 0, 0, 0), Address(1, 1, 1, 1),
                           slash24Mask,
                           "Portal IP is not a usable unicast IPv4 address");
    expectPortalIPRejected(portal, Address(10, 10, 0, 1), Address(0, 0, 0, 0),
                           slash24Mask,
                           "Portal gateway is not a usable unicast IPv4 address");
    expectPortalIPRejected(portal, Address(10, 10, 0, 1), Address(10, 10, 0, 1),
                           Address(255, 0, 255, 0),
                           "Portal subnet mask is invalid or non-contiguous");
    expectPortalIPRejected(portal, Address(10, 10, 0, 1), Address(10, 10, 0, 1),
                           Address(255, 255, 254, 0),
                           "Portal subnet must be between /24 and /28 for SoftAP DHCP");
    expectPortalIPRejected(portal, Address(10, 10, 0, 1), Address(10, 10, 1, 1),
                           slash24Mask,
                           "Portal IP and gateway must be in the same subnet");
    expectPortalIPRejected(portal, Address(10, 10, 0, 0), Address(10, 10, 0, 1),
                           slash24Mask,
                           "Portal IP cannot be the subnet network address");
    expectPortalIPRejected(portal, Address(10, 10, 0, 255), Address(10, 10, 0, 1),
                           slash24Mask,
                           "Portal IP cannot be the subnet broadcast address");
    expectPortalIPRejected(portal, Address(10, 10, 0, 1), Address(10, 10, 0, 0),
                           slash24Mask,
                           "Portal gateway cannot be the subnet network address");
    expectPortalIPRejected(portal, Address(10, 10, 0, 1), Address(10, 10, 0, 255),
                           slash24Mask,
                           "Portal gateway cannot be the subnet broadcast address");
    expectPortalIPRejected(portal, Address(200, 5, 29, 8), Address(200, 5, 29, 8),
                           Address(255, 255, 255, 240),
                           "Portal IP conflicts with the SoftAP DHCP lease range");
    expectPortalIPRejected(portal, Address(200, 5, 29, 12), Address(200, 5, 29, 1),
                           Address(255, 255, 255, 240),
                           "Portal gateway conflicts with the SoftAP DHCP lease range");
    assert(portal.portalIP() == Address(192, 168, 4, 1));

    assert(portal.setPortalIP(Address(200, 5, 29, 12), Address(200, 5, 29, 12),
                              Address(255, 255, 255, 240)));
    assert(portal.lastError().empty());
  }

  // setPortalIP is refused while the portal is active, and accepted again once
  // the portal is stopped.
  {
    resetFakeRuntime();
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(portal.startConfigPortalAsync("IP-Lock", "12345678", 0));
    assert(portal.isPortalActive());

    expectPortalIPRejected(portal, Address(10, 10, 0, 1), Address(10, 10, 0, 1),
                           Address(255, 255, 255, 0), kPortalActiveMessage);
    assert(!portal.setPortalIP(Address(10, 10, 0, 1)));
    assert(portal.lastError() == kPortalActiveMessage);
    assert(portal.portalIP() == Address(192, 168, 4, 1));

    portal.stopConfigPortal();
    assert(!portal.isPortalActive());
    assert(portal.setPortalIP(Address(10, 10, 0, 1)));
    assert(portal.portalIP() == Address(10, 10, 0, 1));
    assert(portal.lastError().empty());
  }

  // setSTAStaticIP follows the STA rules: no SoftAP /24.../28 restriction, but
  // the local address must not equal the gateway, and DNS entries are checked.
  {
    resetFakeRuntime();
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(!portal.isSTAStaticIPConfigured());

    assert(portal.setSTAStaticIP(Address(150, 10, 20, 50),
                                 Address(150, 10, 0, 1),
                                 Address(255, 255, 0, 0)));
    assert(portal.isSTAStaticIPConfigured());
    assert(portal.lastError().empty());

    // A /29 is outside the SoftAP range but valid for STA.
    assert(portal.setSTAStaticIP(Address(192, 168, 1, 50),
                                 Address(192, 168, 1, 49),
                                 Address(255, 255, 255, 248)));
    assert(portal.isSTAStaticIPConfigured());

    // A rejected change keeps the previous static configuration.
    expectSTARejected(portal, Address(150, 10, 20, 50), Address(150, 10, 20, 50),
                      Address(255, 255, 0, 0));  // local == gateway
    assert(portal.isSTAStaticIPConfigured());
    expectSTARejected(portal, Address(0, 0, 0, 0), Address(1, 1, 1, 1),
                      Address(255, 255, 255, 0));
    expectSTARejected(portal, Address(127, 0, 0, 1), Address(127, 0, 0, 2),
                      Address(255, 255, 255, 0));
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 2, 1),
                      Address(255, 255, 255, 0));
    expectSTARejected(portal, Address(192, 168, 1, 0), Address(192, 168, 1, 1),
                      Address(255, 255, 255, 0));
    expectSTARejected(portal, Address(192, 168, 1, 255), Address(192, 168, 1, 1),
                      Address(255, 255, 255, 0));
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 1, 0),
                      Address(255, 255, 255, 0));
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 1, 255),
                      Address(255, 255, 255, 0));
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 1, 1),
                      Address(255, 0, 255, 0));
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 1, 1),
                      Address(0, 0, 0, 0));
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 1, 1),
                      Address(255, 255, 255, 255));

    // DNS rules: a secondary DNS needs a primary, and each entry must be a
    // usable unicast address or 0.0.0.0 (use the DHCP-provided value).
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 1, 1),
                      Address(255, 255, 255, 0), Address(0, 0, 0, 0),
                      Address(1, 1, 1, 1));
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 1, 1),
                      Address(255, 255, 255, 0), Address(127, 0, 0, 1));
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 1, 1),
                      Address(255, 255, 255, 0), Address(8, 8, 8, 8),
                      Address(224, 0, 0, 1));
    assert(portal.isSTAStaticIPConfigured());

    assert(portal.setSTAStaticIP(Address(192, 168, 1, 50),
                                 Address(192, 168, 1, 1),
                                 Address(255, 255, 255, 0)));
    assert(portal.setSTAStaticIP(Address(192, 168, 1, 50),
                                 Address(192, 168, 1, 1),
                                 Address(255, 255, 255, 0), Address(8, 8, 8, 8)));
    assert(portal.setSTAStaticIP(Address(192, 168, 1, 50),
                                 Address(192, 168, 1, 1),
                                 Address(255, 255, 255, 0), Address(8, 8, 8, 8),
                                 Address(1, 1, 1, 1)));
    assert(portal.lastError().empty());

    // useSTADHCP restores DHCP and clears the static configuration.
    portal.useSTADHCP();
    assert(!portal.isSTAStaticIPConfigured());
    assert(portal.lastError().empty());
  }

  // A fresh portal with an invalid STA configuration never becomes static.
  {
    resetFakeRuntime();
    PicoWiFiPortal portal;
    portal.setLogging(false);
    expectSTARejected(portal, Address(192, 168, 1, 50), Address(192, 168, 1, 50),
                      Address(255, 255, 255, 0));
    assert(!portal.isSTAStaticIPConfigured());
  }

  // STA configuration is refused while a Portal connection attempt is running.
  {
    resetFakeRuntime();
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(portal.startConfigPortalAsync("STA-Lock", "12345678", 0));
    httpRequest(portal, "POST", "/save", "ssid=HomeNet&password=12345678");
    assert(portal.isPortalConnectionAttemptActive());

    assert(!portal.setSTAStaticIP(Address(192, 168, 1, 50),
                                  Address(192, 168, 1, 1),
                                  Address(255, 255, 255, 0)));
    assert(portal.lastError() == kSTABusyMessage);
    assert(!portal.isSTAStaticIPConfigured());

    portal.stopConfigPortal();
    assert(portal.setSTAStaticIP(Address(192, 168, 1, 50),
                                 Address(192, 168, 1, 1),
                                 Address(255, 255, 255, 0)));
    assert(portal.isSTAStaticIPConfigured());
  }

  std::cout << "Portal IPv4 validation, DHCP lease, setPortalIP, and "
               "setSTAStaticIP tests passed\n";
  return 0;
}

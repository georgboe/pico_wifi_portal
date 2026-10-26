#include "host/TestAccess.h"

bool headerODRPartA() {
  using Access = PicoWiFiPortalTestAccess;
  const uint32_t slash24 = Access::ipv4(255, 255, 255, 0);
  // Inline header helpers must agree with the copy compiled into Part B.
  return Access::validate(Access::ipv4(10, 10, 0, 1),
                          Access::ipv4(10, 10, 0, 1), slash24) ==
             Access::Result::Valid &&
         Access::dhcpLeaseStart(Access::ipv4(10, 10, 0, 1), slash24) ==
             Access::ipv4(10, 10, 0, 2);
}

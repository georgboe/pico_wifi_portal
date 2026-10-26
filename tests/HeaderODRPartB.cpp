#include "host/TestAccess.h"

bool headerODRPartB() {
  using Access = PicoWiFiPortalTestAccess;
  const uint32_t slash24 = Access::ipv4(255, 255, 255, 0);
  return Access::validate(Access::ipv4(200, 5, 29, 8),
                          Access::ipv4(200, 5, 29, 8), slash24) ==
             Access::Result::Valid &&
         Access::dhcpLeaseStart(Access::ipv4(200, 5, 29, 244), slash24) ==
             Access::ipv4(200, 5, 29, 1);
}

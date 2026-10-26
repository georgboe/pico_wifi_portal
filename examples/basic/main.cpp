/**
 * @file main.cpp
 * @brief Basic PicoWiFiPortal example: connect to saved Wi-Fi or open a
 *        blocking captive portal.
 */

#include <cstdio>

#include "PicoWiFiPortal.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

PicoWiFiPortal wifiPortal;

int main() {
  stdio_init_all();
  sleep_ms(200);

  if (cyw43_arch_init() != 0) {
    printf("CYW43 init failed\n");
    return 1;
  }

  wifiPortal.setHostname("pico-device");
  wifiPortal.onPortalStarted([]() {
    // Defaults to 192.168.4.1
    printf("Setup portal: http://%s\n",
           wifiPortal.portalIP().toString().c_str());
  });

  // Try saved credentials. If they fail, open the captive portal.
  if (!wifiPortal.autoConnect("Pico-Setup", "12345678", 15000, 0)) {
    printf("Wi-Fi setup failed: %s\n", wifiPortal.lastError().c_str());
  } else {
    printf("WiFi connected!\nIP: %s\n",
           wifiPortal.localIP().toString().c_str());
  }

  while (true) {
    wifiPortal.process();
    sleep_ms(2);
  }
}

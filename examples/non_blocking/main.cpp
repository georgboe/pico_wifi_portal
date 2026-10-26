/**
 * @file main.cpp
 * @brief Non-blocking PicoWiFiPortal example.
 */

#include <cstdio>

#include "PicoWiFiPortal.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

PicoWiFiPortal wifiPortal;

int main() {
  stdio_init_all();

  if (cyw43_arch_init() != 0) {
    printf("CYW43 init failed\n");
    return 1;
  }

  wifiPortal.onPortalStarted([]() {
    printf("Portal started\n");
  });

  wifiPortal.onCredentialsSaved([]() {
    printf("Credentials saved\n");
  });

  wifiPortal.onConnected([]() {
    printf("Connected. IP: %s\n", wifiPortal.localIP().toString().c_str());
  });

  if (!wifiPortal.connectSaved(10000)) {
    wifiPortal.startConfigPortalAsync("Pico-Setup", "12345678", 300000);
  }

  while (true) {
    // Required for the async portal and library-managed Auto Reconnect.
    // Keep this loop cooperative: schedule long-running application work with
    // timers and avoid long sleeps or blocking network calls.
    wifiPortal.process();

    // Your application code can continue running here.
    sleep_ms(2);
  }
}

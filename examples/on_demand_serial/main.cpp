/**
 * @file main.cpp
 * @brief Open the Wi-Fi Config Portal on demand from a serial terminal.
 *
 * Type PORTAL and press Enter to open the Config Portal, or ERASE to forget
 * the saved network.
 */

#include <cctype>
#include <cstdio>
#include <cstring>

#include "PicoWiFiPortal.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

constexpr char PORTAL_SSID[] = "Pico-Setup";
constexpr char PORTAL_PASSWORD[] = "12345678";
constexpr uint32_t CONNECT_TIMEOUT_MS = 15000;
constexpr uint32_t PORTAL_TIMEOUT_MS = 300000;  // 5 minutes

PicoWiFiPortal wifiPortal;

char serialCommand[24];
size_t serialCommandLength = 0;
bool portalWasActive = false;

void openConfigPortal() {
  if (wifiPortal.isPortalActive()) {
    printf("Config Portal is already running.\n");
    return;
  }

  printf("Opening Wi-Fi Config Portal...\n");

  if (!wifiPortal.startConfigPortalAsync(PORTAL_SSID, PORTAL_PASSWORD,
                                         PORTAL_TIMEOUT_MS)) {
    printf("Unable to start Config Portal: %s\n",
           wifiPortal.lastError().c_str());
    return;
  }

  portalWasActive = true;
  printf("Connect to AP: %s\n", PORTAL_SSID);
  printf("Open: http://%s\n", wifiPortal.portalIP().toString().c_str());
}

void handleSerialCommand(const char* command) {
  if (strcmp(command, "PORTAL") == 0) {
    openConfigPortal();
    return;
  }
  if (strcmp(command, "ERASE") == 0) {
    if (wifiPortal.eraseCredentials()) {
      printf("Saved Wi-Fi erased.\n");
    } else {
      printf("Erase failed: %s\n", wifiPortal.lastError().c_str());
    }
    return;
  }

  printf("Unknown command: %s\n", command);
  printf("Type PORTAL or ERASE and press Enter.\n");
}

void processSerial() {
  while (true) {
    const int received = getchar_timeout_us(0);
    if (received == PICO_ERROR_TIMEOUT) return;

    if (received == '\r' || received == '\n') {
      if (serialCommandLength == 0) continue;

      serialCommand[serialCommandLength] = '\0';
      handleSerialCommand(serialCommand);
      serialCommandLength = 0;
      continue;
    }

    if (serialCommandLength < sizeof(serialCommand) - 1) {
      serialCommand[serialCommandLength++] =
          static_cast<char>(toupper(static_cast<unsigned char>(received)));
    } else {
      // Drop an overlong command without allocating dynamic memory.
      serialCommandLength = 0;
      printf("Command too long. Type PORTAL and press Enter.\n");
    }
  }
}

int main() {
  stdio_init_all();
  sleep_ms(200);

  if (cyw43_arch_init() != 0) {
    printf("CYW43 init failed\n");
    return 1;
  }

  wifiPortal.onPortalStarted([]() {
    printf("Config Portal started.\n");
  });

  wifiPortal.onCredentialsSaved([]() {
    printf("New Wi-Fi credentials saved.\n");
  });

  wifiPortal.onConnected([]() {
    printf("Wi-Fi connected. IP: %s\n",
           wifiPortal.localIP().toString().c_str());
  });

  if (!wifiPortal.connectSaved(CONNECT_TIMEOUT_MS)) {
    printf("Saved Wi-Fi is unavailable.\n");
    printf("Type PORTAL and press Enter to configure Wi-Fi.\n");
  } else {
    printf("Type PORTAL and press Enter to open Config Portal.\n");
  }

  while (true) {
    // Required for async Config Portal and library-managed Auto Reconnect.
    wifiPortal.process();

    // Non-blocking serial command parser.
    processSerial();

    // Detect when an on-demand Portal has ended.
    if (portalWasActive && !wifiPortal.isPortalActive()) {
      portalWasActive = false;

      if (wifiPortal.isConnected()) {
        printf("Config Portal closed. Wi-Fi connected. IP: %s\n",
               wifiPortal.localIP().toString().c_str());
      } else {
        printf("Config Portal closed: %s\n", wifiPortal.lastError().c_str());
      }

      printf("Type PORTAL and press Enter to open it again.\n");
    }

    sleep_ms(2);
  }
}

# PicoWiFiPortal

[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A Wi-Fi provisioning captive portal for the **Raspberry Pi Pico W** (RP2040)
and **Pico 2 W** (RP2350), written in C++ for the Pico SDK.

On first boot the board opens a SoftAP. Connect with a phone or laptop, pick a
network in the web page, and the credentials are saved to flash. On later boots
the board connects directly and reconnects on its own if the link drops.

This is a port of [ESP32WiFiPortal](https://github.com/NguyenHien-8/ESP32WiFiPortal)
2.1.2 by Tran Nguyen Hien to the CYW43439 radio (cyw43-driver + lwIP).

## Features

It keeps the ESP32 library's behaviour, state machine and web UI:
- SoftAP captive portal with DNS redirection and built-in DHCP (default `192.168.4.1`)
- Configurable portal IP/subnet (`/24`…`/28`) and optional static STA IPv4
- Blocking, non-blocking and on-demand portal modes
- Library-managed auto reconnect with bounded retry bursts and capped backoff
- Automatic recovery of the last saved Wi-Fi after an unsuccessful portal session
- Power-loss-safe, CRC-checked credential storage in flash
- No dependencies beyond the Pico SDK (cyw43-driver + lwIP)

## Minimal example

```cpp
#include "PicoWiFiPortal.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

PicoWiFiPortal portal;

int main() {
  stdio_init_all();
  cyw43_arch_init();  // Required before the first portal call.

  portal.onPortalStarted([]() {
    printf("Open http://%s\n", portal.portalIP().toString().c_str());
  });

  if (!portal.autoConnect("Pico-Setup", "12345678")) {
    printf("%s\n", portal.lastError().c_str());
  }

  while (true) {
    portal.process();  // Also drives auto reconnect.
    sleep_ms(2);
  }
}
```

## Requirements

- [Pico SDK](https://github.com/raspberrypi/pico-sdk) 2.x with submodules
  (cyw43-driver, lwIP)
- `arm-none-eabi-gcc` and CMake ≥ 3.13
- A Pico W or Pico 2 W

## Using it in your project

Add the repository as a submodule (or copy it in), then:

```cmake
add_subdirectory(path/to/pico_wifi_portal pico_wifi_portal)

target_link_libraries(my_app
    pico_stdlib
    pico_cyw43_arch_lwip_threadsafe_background   # or pico_cyw43_arch_lwip_poll
    pico_wifi_portal)
target_include_directories(my_app PRIVATE ${CMAKE_CURRENT_LIST_DIR})  # lwipopts.h
```

Your `lwipopts.h` needs `LWIP_IPV4`, `LWIP_TCP`, `LWIP_UDP`, `LWIP_DHCP` and
(for `setHostname()`) `LWIP_NETIF_HOSTNAME`. `examples/lwipopts.h` is a
known-good starting point; its `MEM_SIZE`, `MEMP_NUM_PBUF` and
`MEMP_NUM_UDP_PCB` are sized for the portal's DNS, DHCP and HTTP servers.

## Building the examples

```sh
export PICO_SDK_PATH=/path/to/pico-sdk
cmake -S examples -B build -DPICO_BOARD=pico_w     # or -DPICO_BOARD=pico2_w
cmake --build build
```

This builds three examples. Flash the `.uf2` from `build/` by holding BOOTSEL
while plugging in the board.

| Example | What it shows |
|---|---|
| `portal_basic` | Blocking `autoConnect()` with a portal fallback |
| `portal_non_blocking` | Portal running while the main loop keeps working |
| `portal_on_demand_serial` | Type `PORTAL` or `ERASE` in a serial terminal |

## Running the tests

The library is tested on the host against a fake Pico SDK (`tests/host`). No
hardware or cross toolchain is needed:

```sh
cmake -S tests -B build-tests
cmake --build build-tests -j
ctest --test-dir build-tests --output-on-failure
```

CI runs these tests and builds the examples for `pico_w` and `pico2_w` on
every push.

## Repository layout

```
include/    Public headers (PicoWiFiPortal.h, CredentialStore.h)
src/        Library sources, lwIP servers and the embedded web page
examples/   Example applications and a known-good lwipopts.h
tests/      Host test suite and the fake Pico SDK it builds against
```

## Threading model

- Call every public method from the thread or core that calls `process()`.
  Callbacks run on that thread.
- Works with both `threadsafe_background` and `poll`. In poll mode,
  `process()` also calls `cyw43_arch_poll()`.
- lwIP and CYW43 callbacks only fill fixed buffers; they never allocate.
  Requests are handled inside `process()`.

## Credential storage

Two 4 KiB flash sectors hold A/B slots with sequence numbers and CRC-32:

- A save goes to the slot that is not the newest valid one. If power is lost
  mid-write, the last committed credentials stay intact.
- An erase first commits a tombstone, then scrubs the old record. An
  interrupted erase can never bring old credentials back.

By default the slots are at `PICO_FLASH_SIZE_BYTES - 16 KiB`. That leaves the
last two sectors free for BTstack. To move them, set the location at compile
time (it must be sector aligned):

```cmake
target_compile_definitions(my_app PRIVATE PICO_WIFI_PORTAL_FLASH_OFFSET=0x1F0000)
```

The library refuses to use a region that overlaps the program image. Flash
writes use `flash_safe_execute()`. If core 1 is running, it must call
`flash_safe_execute_core_init()` (or use `multicore_lockout`); otherwise saving
fails cleanly.

## Differences from the ESP32 version

| ESP32WiFiPortal | PicoWiFiPortal |
|---|---|
| `String`, `IPAddress` | `std::string`, `PicoWiFiPortal::IPv4Address` (`{a,b,c,d}`) |
| Arduino `WebServer`, `DNSServer`, ESP-IDF SoftAP DHCP | Built-in lwIP raw-API servers, bound to the SoftAP interface only (the portal is not reachable from the upstream network) |
| NVS `Preferences` | A/B flash slots (see above); legacy `ssid`/`pass` migration is not applicable |
| `WiFi.onEvent()` reason codes | CYW43 link-status transitions; `lastDisconnectReason()` returns `DisconnectReason` (`LinkLost`, `AuthFailed`, `NetworkNotFound`, `JoinFailed`, `LeftByRequest`) |
| `setAPHidden()` | Removed: the CYW43 driver API has no hidden-SSID option |
| Hostname ≤ 31 bytes | ≤ 63 bytes; must be set before the first Wi-Fi call |
| `ESP.restart()` | `watchdog_reboot()` |
| Properties: flash speed | Properties: chip model (`RP2040` / `RP2350`) |

Behavioural notes:
- A join that the driver reports as failed (`NONET` / `FAIL`) ends the
  attempt right away instead of waiting for the connect timeout. The CYW43
  driver does not retry a failed join on its own.
- STA joins use `CYW43_AUTH_WPA2_AES_PSK` (or open when the password is
  empty). WPA3-only networks are not supported.
- CYW43 has one radio: while STA is associated, the SoftAP follows the STA
  channel regardless of `setAPChannel()`.
- 64-digit hexadecimal PSKs pass validation as in the original. The CYW43
  driver passes them to the firmware with the passphrase flag set; this is
  untested.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Based on ESP32WiFiPortal by Tran Nguyen Hien, also under Apache 2.0. The files
derived from it say so in their headers.

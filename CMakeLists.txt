# PicoWiFiPortal: Pico SDK library target.
#
# Usage from an application CMakeLists.txt (after pico_sdk_init()):
#   add_subdirectory(path/to/pico pico_wifi_portal)
#   target_link_libraries(app
#       pico_stdlib
#       pico_cyw43_arch_lwip_threadsafe_background  # or ..._lwip_poll
#       pico_wifi_portal)
#
# The application provides lwipopts.h on its include path, as with every
# pico_cyw43_arch_lwip_* target.

add_library(pico_wifi_portal INTERFACE)

target_sources(pico_wifi_portal INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/src/PicoWiFiPortal.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/PortalNet.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/CredentialStore.cpp
)

target_include_directories(pico_wifi_portal INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_compile_features(pico_wifi_portal INTERFACE cxx_std_17)

target_link_libraries(pico_wifi_portal INTERFACE
    pico_stdlib
    pico_flash
    pico_unique_id
    hardware_clocks
    hardware_flash
    hardware_watchdog
)

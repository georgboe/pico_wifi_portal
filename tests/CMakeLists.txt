cmake_minimum_required(VERSION 3.16)
project(PicoWiFiPortalHostTests LANGUAGES CXX)

enable_testing()

function(pwp_enable_strict_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive-)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endfunction()

# The library sources built against the fake Pico SDK in host/include.
function(pwp_add_fake_portal name)
  add_library(${name} STATIC
    host/FakePico.cpp
    ../src/PicoWiFiPortal.cpp
    ../src/PortalNet.cpp
    ../src/CredentialStore.cpp
  )
  target_compile_features(${name} PUBLIC cxx_std_17)
  target_compile_definitions(${name} PUBLIC
    PICO_WIFI_PORTAL_ENABLE_TEST_ACCESS=1
    PICO_FLASH_SIZE_BYTES=2097152
    ${ARGN}
  )
  target_include_directories(${name} PUBLIC
    host/include
    host
    ../include
    ../src
  )
  pwp_enable_strict_warnings(${name})
endfunction()

pwp_add_fake_portal(fake_pico_portal)
# Credential region placed inside the fake program image (offset 0x10000).
pwp_add_fake_portal(fake_pico_portal_bad_flash PICO_WIFI_PORTAL_FLASH_OFFSET=0x8000)

function(pwp_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE fake_pico_portal)
  pwp_enable_strict_warnings(${name})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

pwp_add_test(portal_network_validation PortalNetworkValidationTest.cpp)
pwp_add_test(portal_lifecycle PortalLifecycleTest.cpp)
pwp_add_test(credential_storage CredentialStorageTest.cpp)
pwp_add_test(auto_reconnect AutoReconnectTest.cpp)
pwp_add_test(portal_page PortalPageTest.cpp)
pwp_add_test(header_odr HeaderODRTest.cpp HeaderODRPartA.cpp HeaderODRPartB.cpp)
pwp_add_test(wifi_driver_policy WiFiDriverPolicyTest.cpp)
pwp_add_test(portal_scan PortalScanTest.cpp)

add_executable(credential_region_unusable CredentialRegionUnusableTest.cpp)
target_link_libraries(credential_region_unusable PRIVATE fake_pico_portal_bad_flash)
pwp_enable_strict_warnings(credential_region_unusable)
add_test(NAME credential_region_unusable COMMAND credential_region_unusable)

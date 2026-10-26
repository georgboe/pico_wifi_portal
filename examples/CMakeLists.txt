cmake_minimum_required(VERSION 3.13)

# Build for Pico W by default; pass -DPICO_BOARD=pico2_w for Pico 2 W.
if (NOT DEFINED PICO_BOARD)
    set(PICO_BOARD pico_w CACHE STRING "Board type")
endif()

include(pico_sdk_import.cmake)

project(pico_wifi_portal_examples C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

if (NOT PICO_CYW43_SUPPORTED)
    message(FATAL_ERROR "PICO_BOARD=${PICO_BOARD} has no CYW43 Wi-Fi chip; use pico_w or pico2_w")
endif()

add_subdirectory(.. pico_wifi_portal)

function(add_portal_example name source)
    add_executable(${name} ${source})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_LIST_DIR})
    target_compile_options(${name} PRIVATE -Wall -Wextra)
    target_link_libraries(${name}
        pico_stdlib
        pico_cyw43_arch_lwip_threadsafe_background
        pico_wifi_portal
    )
    pico_enable_stdio_usb(${name} 1)
    pico_enable_stdio_uart(${name} 1)
    pico_add_extra_outputs(${name})
endfunction()

add_portal_example(portal_basic basic/main.cpp)
add_portal_example(portal_non_blocking non_blocking/main.cpp)
add_portal_example(portal_on_demand_serial on_demand_serial/main.cpp)

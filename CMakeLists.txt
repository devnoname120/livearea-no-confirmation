cmake_minimum_required(VERSION 3.10)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(DEFINED ENV{VITASDK})
        set(CMAKE_TOOLCHAIN_FILE
            "$ENV{VITASDK}/share/vita.toolchain.cmake"
            CACHE PATH "VitaSDK toolchain file")
    else()
        message(FATAL_ERROR "Set VITASDK or CMAKE_TOOLCHAIN_FILE")
    endif()
endif()

project(livearea_no_confirmation VERSION 1.1.0 LANGUAGES C)
include("${VITASDK}/share/vita.cmake" REQUIRED)

add_executable(livearea_no_confirmation
    src/main.c
    src/plugin.c
    src/signature.c
)

target_include_directories(livearea_no_confirmation PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(livearea_no_confirmation PRIVATE
    -Wall
    -Wextra
    -Werror
    -O2
    -ffreestanding
    -fno-builtin
    -fno-stack-protector
    -ffunction-sections
    -fdata-sections
    -fno-pic
    -fno-PIC
)

target_link_libraries(livearea_no_confirmation PRIVATE
    taihen_stub
    SceKernelModulemgr_stub
)

set_target_properties(livearea_no_confirmation PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    LINK_FLAGS "-nostdlib -Wl,-q -Wl,--gc-sections -Wl,-e,module_start -Wl,--undefined=module_start -Wl,--undefined=module_stop"
)

vita_create_self(
    livearea_no_confirmation.suprx
    livearea_no_confirmation
    UNSAFE
    CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/livearea_no_confirmation.yml)

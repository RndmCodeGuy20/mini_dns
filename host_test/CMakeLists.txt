# Host-side unit test project for the pure DNS wire-format functions
# (main/dns_wire.h/.cpp) — see ARCHITECTURE.md's "No automated tests"
# gotcha and docs/superpowers/specs/2026-07-21-edge-dns-phase6-hardening-design.md.
#
# dns_wire.cpp has no FreeRTOS/lwIP dependency, so it builds and runs on
# ESP-IDF's "linux" target with no hardware/QEMU involved:
#
#   idf.py --preview set-target linux -C host_test build
#   ./host_test/build/host_test.elf
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(host_test)

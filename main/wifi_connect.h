#pragma once

// Brings up Wi-Fi station mode using stored credentials (esp_wifi's own NVS
// blob — see wifi_connect.cpp), seeding from wifi_credentials.h on first
// boot if nothing is stored yet. Blocks up to 30s waiting for an initial
// IP. Returns false if there is nothing to try (no stored config and no
// seed) or the 30s timeout elapses without connecting; true once connected.
// After a first successful connect, later disconnects retry indefinitely
// in the background regardless of this return value — see the
// WIFI_EVENT_STA_DISCONNECTED handler in wifi_connect.cpp.
bool wifi_connect_sta();

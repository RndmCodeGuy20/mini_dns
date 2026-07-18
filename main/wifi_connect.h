#pragma once

// Brings up Wi-Fi station mode with hardcoded credentials, blocks until
// an IP is obtained via DHCP, retries indefinitely on failure.
void wifi_connect();

# admin_credentials.h is gitignored (like wifi_credentials.h) and must be
# created by hand before building — see README.md. Required symbols:
# ADMIN_USER, ADMIN_PASS (both const char*).
idf_component_register(SRCS "main.cpp" "wifi_connect.cpp" "dns_server.cpp" "dns_wire.cpp"
                            "dns_cache.cpp" "dns_forwarder.cpp" "dns_blocklist.cpp"
                            "dns_metrics.cpp" "dns_record_store.cpp" "http_server.cpp"
                            "mdns_responder.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi esp_netif esp_event nvs_flash lwip esp_http_server json
                             esp_psram esp_timer mdns mbedtls)

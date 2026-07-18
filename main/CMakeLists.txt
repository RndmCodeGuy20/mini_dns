idf_component_register(SRCS "main.cpp" "wifi_connect.cpp" "dns_server.cpp" "http_server.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi esp_netif esp_event nvs_flash lwip esp_http_server json)

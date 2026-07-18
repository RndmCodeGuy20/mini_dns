#include "dns_server.h"
#include "http_server.h"
#include "wifi_connect.h"

extern "C" void app_main(void)
{
    wifi_connect();
    dns_server_start();
    http_server_start();
}

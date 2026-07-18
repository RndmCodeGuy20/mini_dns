#pragma once

// Starts the HTTP server on port 80 (esp_http_server default) and
// registers the "/" handler that serves a static placeholder page.
// esp_http_server manages its own FreeRTOS task internally, so unlike
// dns_server_start() this call does not spawn one explicitly — it just
// configures and starts the server, then returns.
void http_server_start();

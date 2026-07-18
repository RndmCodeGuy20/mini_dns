#pragma once

// Starts the DNS UDP listener as its own FreeRTOS task. Binds to
// INADDR_ANY:53, parses the DNS header and question section of each
// packet, and logs the queried hostname. Non-blocking: returns
// immediately after creating the task.
void dns_server_start();

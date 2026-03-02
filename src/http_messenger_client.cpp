#include "http_messenger_client.h"

#include <iostream>
#include <stdexcept>
#include <thread>
#include <chrono>

static const std::string HTTP_ROUTE = "socketio/?EIO=4&transport=polling";

HTTPMessengerClient::HTTPMessengerClient(
    const std::string& uri,
    const std::vector<uint8_t>& encryption_key
) : uri_(uri + "/" + HTTP_ROUTE),
    encryption_key_(encryption_key) {}

void HTTPMessengerClient::connect() {
    // TODO: Implement HTTP connection using a library (e.g., libcurl, cpp-httplib)
    // 1. POST serialized CheckInMessage to uri_
    // 2. Deserialize response to get assigned messenger_id
    // 3. Enter poll_server() loop

    std::cout << "[HTTP] Connecting to " << uri_ << std::endl;
    throw std::runtime_error("HTTP transport not yet implemented");
}

void HTTPMessengerClient::send_downstream_message(const Message& message) {
    std::lock_guard<std::mutex> lock(downstream_mutex_);
    downstream_messages_.push(message);
}

void HTTPMessengerClient::handle_message(const Message& message) {
    MessengerClient::handle_message(message);
}

void HTTPMessengerClient::poll_server() {
    // TODO: Implement HTTP polling loop
    // 1. Build list of downstream messages (CheckIn + queued messages)
    // 2. POST serialized messages to uri_
    // 3. Deserialize response and handle each message
    // 4. Sleep between polls
}

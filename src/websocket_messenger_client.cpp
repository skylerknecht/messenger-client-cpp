#include "websocket_messenger_client.h"

#include <iostream>
#include <stdexcept>
#include <thread>
#include <chrono>

static const std::string WS_ROUTE = "socketio/?EIO=4&transport=websocket";

WebSocketMessengerClient::WebSocketMessengerClient(
    const std::string& uri,
    const std::vector<uint8_t>& encryption_key
) : uri_(uri + "/" + WS_ROUTE),
    encryption_key_(encryption_key) {}

void WebSocketMessengerClient::connect() {
    // TODO: Implement WebSocket connection using a library (e.g., libwebsockets, Boost.Beast)
    // 1. Establish WebSocket connection to uri_
    // 2. Send CheckInMessage with empty messenger_id
    // 3. Receive CheckInMessage response with assigned messenger_id
    // 4. Start receive_messages() and send_messages() loops

    std::cout << "[WebSocket] Connecting to " << uri_ << std::endl;
    throw std::runtime_error("WebSocket transport not yet implemented");
}

void WebSocketMessengerClient::send_downstream_message(const Message& message) {
    std::lock_guard<std::mutex> lock(downstream_mutex_);
    downstream_messages_.push(message);
}

void WebSocketMessengerClient::handle_message(const Message& message) {
    if (auto* cim = std::get_if<CheckInMessage>(&message)) {
        messenger_id_ = cim->messenger_id;
    } else {
        MessengerClient::handle_message(message);
    }
}

void WebSocketMessengerClient::receive_messages() {
    // TODO: Implement WebSocket receive loop
    // 1. Read binary frames from the WebSocket
    // 2. Accumulate until end-of-message
    // 3. Deserialize and call handle_message for each
}

void WebSocketMessengerClient::send_messages() {
    // TODO: Implement WebSocket send loop
    // 1. Dequeue downstream messages
    // 2. Prepend CheckInMessage with messenger_id_
    // 3. Serialize and send as binary WebSocket frame
}

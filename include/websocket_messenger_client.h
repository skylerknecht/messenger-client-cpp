#ifndef WEBSOCKET_MESSENGER_CLIENT_H
#define WEBSOCKET_MESSENGER_CLIENT_H

#include "messenger_client.h"

#include <mutex>
#include <queue>
#include <string>
#include <vector>

class WebSocketMessengerClient : public MessengerClient {
public:
    WebSocketMessengerClient(const std::string& uri, const std::vector<uint8_t>& encryption_key);
    ~WebSocketMessengerClient() override = default;

    void connect() override;
    void send_downstream_message(const Message& message) override;
    void handle_message(const Message& message) override;

private:
    void receive_messages();
    void send_messages();

    std::string uri_;
    std::vector<uint8_t> encryption_key_;
    std::string messenger_id_;

    std::queue<Message> downstream_messages_;
    std::mutex downstream_mutex_;
};

#endif // WEBSOCKET_MESSENGER_CLIENT_H

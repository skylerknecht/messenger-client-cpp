#ifndef HTTP_MESSENGER_CLIENT_H
#define HTTP_MESSENGER_CLIENT_H

#include "messenger_client.h"

#include <mutex>
#include <queue>
#include <string>
#include <vector>

class HTTPMessengerClient : public MessengerClient {
public:
    HTTPMessengerClient(const std::string& uri, const std::vector<uint8_t>& encryption_key);
    ~HTTPMessengerClient() override = default;

    void connect() override;
    void send_downstream_message(const Message& message) override;
    void handle_message(const Message& message) override;

private:
    void poll_server();

    std::string uri_;
    std::vector<uint8_t> encryption_key_;
    std::string messenger_id_;

    std::queue<Message> downstream_messages_;
    std::mutex downstream_mutex_;
};

#endif // HTTP_MESSENGER_CLIENT_H

#ifndef WEBSOCKET_MESSENGER_CLIENT_H
#define WEBSOCKET_MESSENGER_CLIENT_H

#include "messenger_client.h"

#include <atomic>
#include <windows.h>
#include <winhttp.h>

#include <mutex>
#include <queue>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

class WebSocketMessengerClient : public MessengerClient {
public:
    WebSocketMessengerClient(const std::string& uri, const std::vector<uint8_t>& encryption_key,
                             const std::string& user_agent);
    ~WebSocketMessengerClient() override;

    void connect() override;
    void start() override;
    void send_downstream_message(const Message& message) override;
    void handle_message(const Message& message) override;

private:
    void receive_messages();
    void send_messages();
    void cleanup();

    std::string host_;
    INTERNET_PORT port_;
    std::string path_;
    bool use_ssl_;
    std::string user_agent_;

    std::string uri_;
    std::vector<uint8_t> encryption_key_;
    std::string messenger_id_;

    HINTERNET h_session_ = nullptr;
    HINTERNET h_connect_ = nullptr;
    HINTERNET h_request_ = nullptr;
    HINTERNET h_websocket_ = nullptr;

    std::atomic<bool> running_{false};

    std::queue<Message> downstream_messages_;
    std::mutex downstream_mutex_;
};

#endif // WEBSOCKET_MESSENGER_CLIENT_H

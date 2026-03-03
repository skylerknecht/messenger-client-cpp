#ifndef HTTP_MESSENGER_CLIENT_H
#define HTTP_MESSENGER_CLIENT_H

#include "messenger_client.h"

#include <windows.h>
#include <winhttp.h>

#include <mutex>
#include <queue>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

class HTTPMessengerClient : public MessengerClient {
public:
    HTTPMessengerClient(const std::string& uri, const std::vector<uint8_t>& encryption_key,
                        const std::string& user_agent);
    ~HTTPMessengerClient() override;

    void connect() override;
    void start() override;
    void send_downstream_message(const Message& message) override;
    void handle_message(const Message& message) override;

private:
    void poll_server();
    std::vector<uint8_t> post_binary(const std::vector<uint8_t>& data);
    void cleanup();

    std::string host_;
    INTERNET_PORT port_;
    std::string path_;
    bool use_ssl_;
    std::string user_agent_;

    std::vector<uint8_t> encryption_key_;
    std::string messenger_id_;

    HINTERNET h_session_ = nullptr;
    HINTERNET h_connect_ = nullptr;

    std::queue<Message> downstream_messages_;
    std::mutex downstream_mutex_;
};

#endif // HTTP_MESSENGER_CLIENT_H

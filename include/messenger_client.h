#ifndef MESSENGER_CLIENT_H
#define MESSENGER_CLIENT_H

#include "message.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

class MessengerClient {
public:
    virtual ~MessengerClient() = default;

    virtual void connect() = 0;
    virtual void start() = 0;
    virtual void send_downstream_message(const Message& message) = 0;
    virtual void handle_message(const Message& message);

    std::vector<Message> deserialize_messages(const std::vector<uint8_t>& encryption_key, const std::vector<uint8_t>& raw_data);
    std::vector<uint8_t> serialize_messages(const std::vector<uint8_t>& encryption_key, const std::vector<Message>& messages);

    void handle_initiate_forwarder_client_req(const InitiateForwarderClientReq& message);
    void stream(const std::string& forwarder_client_id);

    std::map<std::string, SOCKET> forwarder_clients;
    std::mutex forwarder_clients_mutex;
};

#endif // MESSENGER_CLIENT_H

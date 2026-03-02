#include "messenger_client.h"

#include <iostream>
#include <cstring>
#include <stdexcept>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

std::vector<Message> MessengerClient::deserialize_messages(
    const std::vector<uint8_t>& encryption_key,
    const std::vector<uint8_t>& raw_data
) {
    std::vector<Message> messages;
    std::vector<uint8_t> leftover = raw_data;

    while (!leftover.empty()) {
        auto [new_leftover, parsed_message] = MessageParser::deserialize_message(encryption_key, leftover);
        messages.push_back(parsed_message);
        leftover = new_leftover;
    }

    return messages;
}

std::vector<uint8_t> MessengerClient::serialize_messages(
    const std::vector<uint8_t>& encryption_key,
    const std::vector<Message>& messages
) {
    std::vector<uint8_t> result;

    for (const auto& message : messages) {
        auto serialized = MessageBuilder::serialize_message(encryption_key, message);
        result.insert(result.end(), serialized.begin(), serialized.end());
    }

    return result;
}

void MessengerClient::handle_message(const Message& message) {
    if (auto* req = std::get_if<InitiateForwarderClientReq>(&message)) {
        handle_initiate_forwarder_client_req(*req);
    } else if (auto* rep = std::get_if<InitiateForwarderClientRep>(&message)) {
        stream(rep->forwarder_client_id);
    } else if (auto* sdm = std::get_if<SendDataMessage>(&message)) {
        std::lock_guard<std::mutex> lock(forwarder_clients_mutex);
        auto it = forwarder_clients.find(sdm->forwarder_client_id);
        if (it != forwarder_clients.end()) {
            if (sdm->data.empty()) {
                close(it->second);
                forwarder_clients.erase(it);
            } else {
                send(it->second, sdm->data.data(), sdm->data.size(), 0);
            }
        }
    } else if (auto* cim = std::get_if<CheckInMessage>(&message)) {
        // No-op for check-in messages
    }
}

void MessengerClient::handle_initiate_forwarder_client_req(const InitiateForwarderClientReq& message) {
    struct addrinfo hints{}, *result;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(message.port);

    int status = getaddrinfo(message.ip_address.c_str(), port_str.c_str(), &hints, &result);
    if (status != 0) {
        auto rep = InitiateForwarderClientRep{
            message.forwarder_client_id, "0.0.0.0", 0, 1, 0x04
        };
        send_downstream_message(Message{rep});
        return;
    }

    int sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(result);
        auto rep = InitiateForwarderClientRep{
            message.forwarder_client_id, "0.0.0.0", 0, 1, 0x01
        };
        send_downstream_message(Message{rep});
        return;
    }

    if (::connect(sock, result->ai_addr, result->ai_addrlen) < 0) {
        freeaddrinfo(result);
        close(sock);

        uint32_t reason = 0x01;
        if (errno == ENETUNREACH) reason = 0x03;
        else if (errno == EHOSTUNREACH) reason = 0x04;
        else if (errno == ECONNREFUSED) reason = 0x05;
        else if (errno == ETIMEDOUT) reason = 0x06;

        auto rep = InitiateForwarderClientRep{
            message.forwarder_client_id, "0.0.0.0", 0, 1, reason
        };
        send_downstream_message(Message{rep});
        return;
    }

    freeaddrinfo(result);

    // Get local address info
    struct sockaddr_storage local_addr{};
    socklen_t addr_len = sizeof(local_addr);
    getsockname(sock, reinterpret_cast<struct sockaddr*>(&local_addr), &addr_len);

    char bind_address[INET6_ADDRSTRLEN];
    uint16_t bind_port;
    uint32_t atype;

    if (local_addr.ss_family == AF_INET) {
        auto* addr4 = reinterpret_cast<struct sockaddr_in*>(&local_addr);
        inet_ntop(AF_INET, &addr4->sin_addr, bind_address, sizeof(bind_address));
        bind_port = ntohs(addr4->sin_port);
        atype = 1;
    } else {
        auto* addr6 = reinterpret_cast<struct sockaddr_in6*>(&local_addr);
        inet_ntop(AF_INET6, &addr6->sin6_addr, bind_address, sizeof(bind_address));
        bind_port = ntohs(addr6->sin6_port);
        atype = 4;
    }

    {
        std::lock_guard<std::mutex> lock(forwarder_clients_mutex);
        forwarder_clients[message.forwarder_client_id] = sock;
    }

    auto rep = InitiateForwarderClientRep{
        message.forwarder_client_id,
        std::string(bind_address),
        bind_port,
        atype,
        0
    };
    send_downstream_message(Message{rep});
    stream(message.forwarder_client_id);
}

void MessengerClient::stream(const std::string& forwarder_client_id) {
    int client_fd;
    {
        std::lock_guard<std::mutex> lock(forwarder_clients_mutex);
        auto it = forwarder_clients.find(forwarder_client_id);
        if (it == forwarder_clients.end()) return;
        client_fd = it->second;
    }

    uint8_t buffer[4096];
    ssize_t bytes_read;

    while ((bytes_read = recv(client_fd, buffer, sizeof(buffer), 0)) > 0) {
        std::vector<uint8_t> data(buffer, buffer + bytes_read);
        auto sdm = SendDataMessage{forwarder_client_id, data};
        send_downstream_message(Message{sdm});
    }

    {
        std::lock_guard<std::mutex> lock(forwarder_clients_mutex);
        forwarder_clients.erase(forwarder_client_id);
    }

    close(client_fd);

    auto close_msg = SendDataMessage{forwarder_client_id, {}};
    send_downstream_message(Message{close_msg});
}

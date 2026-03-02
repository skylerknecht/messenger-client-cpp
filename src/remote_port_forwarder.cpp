#include "remote_port_forwarder.h"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <random>

static std::string random_alphanum(int len = 10) {
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(chars) - 2);

    std::string result;
    result.reserve(len);
    for (int i = 0; i < len; i++) {
        result += chars[dis(gen)];
    }
    return result;
}

RemotePortForwarder::RemotePortForwarder(MessengerClient& messenger, const std::string& config)
    : messenger_(messenger) {
    parse_config(config);
}

void RemotePortForwarder::parse_config(const std::string& config) {
    std::istringstream stream(config);
    std::string token;
    std::vector<std::string> parts;

    while (std::getline(stream, token, ':')) {
        parts.push_back(token);
    }

    if (parts.size() != 4) {
        throw std::runtime_error(
            "Invalid config format. Expected: LISTENING-HOST:LISTENING-PORT:DESTINATION-HOST:DESTINATION-PORT"
        );
    }

    listening_host_ = parts[0];
    listening_port_ = std::stoi(parts[1]);
    destination_host_ = parts[2];
    destination_port_ = std::stoi(parts[3]);
}

void RemotePortForwarder::start() {
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        std::cerr << listening_host_ << ":" << listening_port_
                  << " failed to create socket" << std::endl;
        return;
    }

    char opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(listening_port_));
    InetPtonA(AF_INET, listening_host_.c_str(), &addr.sin_addr);

    if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << listening_host_ << ":" << listening_port_
                  << " is already in use or encountered an error" << std::endl;
        closesocket(server_fd);
        return;
    }

    if (listen(server_fd, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Failed to listen on " << listening_host_ << ":" << listening_port_ << std::endl;
        closesocket(server_fd);
        return;
    }

    std::cout << "[+] Remote Port Forwarder listening on "
              << listening_host_ << ":" << listening_port_ << std::endl;

    while (true) {
        SOCKET client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd == INVALID_SOCKET) {
            continue;
        }

        std::thread(&RemotePortForwarder::handle_client, this, client_fd).detach();
    }
}

void RemotePortForwarder::handle_client(SOCKET client_fd) {
    std::string client_id = random_alphanum(10);

    {
        std::lock_guard<std::mutex> lock(messenger_.forwarder_clients_mutex);
        messenger_.forwarder_clients[client_id] = client_fd;
    }

    auto req = InitiateForwarderClientReq{
        client_id,
        destination_host_,
        static_cast<uint32_t>(destination_port_)
    };
    messenger_.send_downstream_message(Message{req});
}

#include "crypto.h"
#include "message.h"
#include "messenger_client.h"
#include "websocket_messenger_client.h"
#include "http_messenger_client.h"
#include "remote_port_forwarder.h"

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

static const std::string USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0";

static bool try_ws(const std::string& url, const std::vector<uint8_t>& encryption_key,
                   const std::vector<std::string>& remote_port_forwards,
                   std::unique_ptr<MessengerClient>& client) {
    try {
        std::cout << "[WebSocket] Trying " << url << std::endl;
        auto ws_client = std::make_unique<WebSocketMessengerClient>(url, encryption_key);
        ws_client->connect();
        client = std::move(ws_client);

        for (const auto& config : remote_port_forwards) {
            auto forwarder = std::make_unique<RemotePortForwarder>(*client, config);
            std::thread([f = std::move(forwarder)]() { f->start(); }).detach();
            std::cout << "Started RemotePortForwarder with config: " << config << std::endl;
        }

        return true;
    } catch (const std::exception& ex) {
        std::cout << "[WebSocket] Failed to connect to " << url << ": " << ex.what() << std::endl;
        return false;
    }
}

static bool try_http(const std::string& url, const std::vector<uint8_t>& encryption_key,
                     const std::vector<std::string>& remote_port_forwards,
                     std::unique_ptr<MessengerClient>& client) {
    try {
        std::cout << "[HTTP] Trying " << url << std::endl;
        auto http_client = std::make_unique<HTTPMessengerClient>(url, encryption_key);
        http_client->connect();
        client = std::move(http_client);

        for (const auto& config : remote_port_forwards) {
            auto forwarder = std::make_unique<RemotePortForwarder>(*client, config);
            std::thread([f = std::move(forwarder)]() { f->start(); }).detach();
            std::cout << "Started RemotePortForwarder with config: " << config << std::endl;
        }

        return true;
    } catch (const std::exception& ex) {
        std::cout << "[HTTP] Failed to connect to " << url << ": " << ex.what() << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: messenger-client-cpp <URL> <Encryption_Key> [remote_port_forwards...]" << std::endl;
        return 1;
    }

    std::string uri = argv[1];
    std::vector<uint8_t> encryption_key = Crypto::hash(argv[2]);

    std::vector<std::string> remote_port_forwards;
    for (int i = 3; i < argc; i++) {
        remote_port_forwards.emplace_back(argv[i]);
    }

    // Trim trailing slashes
    while (!uri.empty() && uri.back() == '/') {
        uri.pop_back();
    }

    std::vector<std::string> attempts;

    auto pos = uri.find("://");
    if (pos != std::string::npos) {
        std::string schemes = uri.substr(0, pos);
        uri = uri.substr(pos + 3);

        std::istringstream stream(schemes);
        std::string scheme;
        while (std::getline(stream, scheme, '+')) {
            attempts.push_back(scheme);
        }
    } else {
        attempts = {"ws", "http", "wss", "https"};
    }

    std::unique_ptr<MessengerClient> client;

    for (const auto& attempt : attempts) {
        std::string url = attempt + "://" + uri;

        bool success = false;
        if (attempt.find("http") != std::string::npos) {
            success = try_http(url, encryption_key, remote_port_forwards, client);
        } else if (attempt.find("ws") != std::string::npos) {
            success = try_ws(url, encryption_key, remote_port_forwards, client);
        }

        if (success) {
            // Block forever
            std::promise<void>().get_future().wait();
            return 0;
        }
    }

    std::cout << "All connection attempts failed." << std::endl;
    return 1;
}

#include "crypto.h"
#include "message.h"
#include "messenger_client.h"
#include "websocket_messenger_client.h"
#include "http_messenger_client.h"
#include "remote_port_forwarder.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

static const std::string DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

int main(int argc, char* argv[]) {
    // Initialize Winsock
    WSADATA wsa_data;
    int wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_result != 0) {
        std::cerr << "WSAStartup failed: " << wsa_result << std::endl;
        return 1;
    }

    if (argc < 3) {
        std::cout << "Usage: messenger-client-cpp <URL> <Encryption_Key> [remote_port_forwards...]" << std::endl;
        WSACleanup();
        return 1;
    }

    std::string uri = argv[1];
    std::vector<uint8_t> encryption_key = Crypto::hash(argv[2]);
    std::string user_agent = DEFAULT_USER_AGENT;

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

    // Initial connection: try each scheme, first success wins
    std::unique_ptr<MessengerClient> client;

    for (const auto& attempt : attempts) {
        std::string url = attempt + "://" + uri;

        try {
            if (attempt.find("ws") != std::string::npos) {
                std::cout << "[*] Attempting to connect over " << attempt << std::endl;
                client = std::make_unique<WebSocketMessengerClient>(url, encryption_key, user_agent);
            } else if (attempt.find("http") != std::string::npos) {
                std::cout << "[*] Attempting to connect over " << attempt << std::endl;
                client = std::make_unique<HTTPMessengerClient>(url, encryption_key, user_agent);
            } else {
                continue;
            }

            client->connect();
            break;
        } catch (const std::exception& ex) {
            std::cerr << "[!] Failed to connect: " << ex.what() << std::endl;
            client.reset();
            continue;
        }
    }

    if (!client) {
        std::cout << "All connection attempts failed." << std::endl;
        WSACleanup();
        return 1;
    }

    // Start remote port forwarders (once, they hold a reference to client)
    for (const auto& config : remote_port_forwards) {
        auto forwarder = std::make_unique<RemotePortForwarder>(*client, config);
        std::thread([f = std::move(forwarder)]() { f->start(); }).detach();
        std::cout << "Started RemotePortForwarder with config: " << config << std::endl;
    }

    // Run the message loop (blocks until disconnect)
    try {
        client->start();
    } catch (const std::exception& ex) {
        std::cerr << "[!] " << ex.what() << std::endl;
    }

    // Reconnection loop
    int retry_attempts = 5;
    double retry_duration = 60.0;
    int attempts_count = 1;
    double sleep_time = retry_duration / retry_attempts;

    while (attempts_count <= retry_attempts) {
        std::cout << "[*] Attempting to reconnect (attempt #" << attempts_count
                  << "/" << retry_attempts << ")" << std::endl;

        std::this_thread::sleep_for(
            std::chrono::milliseconds(static_cast<int>(sleep_time * 1000)));

        try {
            client->connect();
            std::cout << "[+] Reconnected" << std::endl;
            attempts_count = 1; // reset on successful reconnect
            client->start();    // blocks until next disconnect
        } catch (const std::exception& ex) {
            std::cerr << "[!] Reconnect failed: " << ex.what() << std::endl;
            attempts_count++;
        }
    }

    std::cout << "[*] Retry attempts exhausted, exiting." << std::endl;
    WSACleanup();
    return 0;
}

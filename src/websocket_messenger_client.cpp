#include "websocket_messenger_client.h"

#include <iostream>
#include <stdexcept>
#include <thread>
#include <chrono>

static const std::string WS_ROUTE = "socketio/?EIO=4&transport=websocket";

static std::wstring to_wstring(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

static void parse_ws_url(const std::string& url,
                         std::string& host, INTERNET_PORT& port,
                         std::string& path, bool& use_ssl) {
    std::string remainder = url;

    if (remainder.rfind("wss://", 0) == 0) {
        use_ssl = true;
        remainder = remainder.substr(6);
    } else if (remainder.rfind("ws://", 0) == 0) {
        use_ssl = false;
        remainder = remainder.substr(5);
    } else {
        use_ssl = false;
    }

    while (!remainder.empty() && remainder.back() == '/') {
        remainder.pop_back();
    }

    auto slash_pos = remainder.find('/');
    std::string host_port;
    if (slash_pos != std::string::npos) {
        host_port = remainder.substr(0, slash_pos);
        path = remainder.substr(slash_pos);
    } else {
        host_port = remainder;
        path = "/";
    }

    if (path.back() != '/') path += '/';
    path += WS_ROUTE;

    auto colon_pos = host_port.find(':');
    if (colon_pos != std::string::npos) {
        host = host_port.substr(0, colon_pos);
        port = static_cast<INTERNET_PORT>(std::stoi(host_port.substr(colon_pos + 1)));
    } else {
        host = host_port;
        port = use_ssl ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    }
}

WebSocketMessengerClient::WebSocketMessengerClient(
    const std::string& uri,
    const std::vector<uint8_t>& encryption_key
) : encryption_key_(encryption_key) {
    std::string host, path;
    INTERNET_PORT port;
    bool use_ssl;
    parse_ws_url(uri, host, port, path, use_ssl);

    // Store full URI for logging
    uri_ = (use_ssl ? "wss://" : "ws://") + host + ":" + std::to_string(port) + path;

    // Open session
    h_session_ = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!h_session_) {
        throw std::runtime_error("WinHttpOpen failed: " + std::to_string(GetLastError()));
    }

    // Connect to host
    h_connect_ = WinHttpConnect(h_session_, to_wstring(host).c_str(), port, 0);
    if (!h_connect_) {
        cleanup();
        throw std::runtime_error("WinHttpConnect failed: " + std::to_string(GetLastError()));
    }

    // Open request for WebSocket upgrade
    h_request_ = WinHttpOpenRequest(
        h_connect_,
        L"GET",
        to_wstring(path).c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        use_ssl ? WINHTTP_FLAG_SECURE : 0
    );
    if (!h_request_) {
        cleanup();
        throw std::runtime_error("WinHttpOpenRequest failed: " + std::to_string(GetLastError()));
    }

    // Ignore SSL cert errors
    if (use_ssl) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(h_request_, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    // Set WebSocket upgrade option
    BOOL result = WinHttpSetOption(h_request_, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0);
    if (!result) {
        cleanup();
        throw std::runtime_error("Failed to set WebSocket upgrade option: " + std::to_string(GetLastError()));
    }
}

WebSocketMessengerClient::~WebSocketMessengerClient() {
    cleanup();
}

void WebSocketMessengerClient::cleanup() {
    if (h_websocket_) { WinHttpCloseHandle(h_websocket_); h_websocket_ = nullptr; }
    if (h_request_) { WinHttpCloseHandle(h_request_); h_request_ = nullptr; }
    if (h_connect_) { WinHttpCloseHandle(h_connect_); h_connect_ = nullptr; }
    if (h_session_) { WinHttpCloseHandle(h_session_); h_session_ = nullptr; }
}

void WebSocketMessengerClient::connect() {
    std::cout << "[WebSocket] Connecting to " << uri_ << std::endl;

    // Send the HTTP request to initiate WebSocket handshake
    BOOL result = WinHttpSendRequest(
        h_request_,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0,
        0, 0
    );
    if (!result) {
        throw std::runtime_error("WinHttpSendRequest failed: " + std::to_string(GetLastError()));
    }

    result = WinHttpReceiveResponse(h_request_, nullptr);
    if (!result) {
        throw std::runtime_error("WinHttpReceiveResponse failed: " + std::to_string(GetLastError()));
    }

    // Complete the WebSocket upgrade
    h_websocket_ = WinHttpWebSocketCompleteUpgrade(h_request_, 0);
    if (!h_websocket_) {
        throw std::runtime_error("WinHttpWebSocketCompleteUpgrade failed: " + std::to_string(GetLastError()));
    }

    // The request handle is no longer needed after upgrade
    WinHttpCloseHandle(h_request_);
    h_request_ = nullptr;

    // Send initial CheckInMessage
    auto check_in = CheckInMessage{""};
    std::vector<Message> msgs = {Message{check_in}};
    auto payload = serialize_messages(encryption_key_, msgs);

    DWORD err = WinHttpWebSocketSend(h_websocket_, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                                      payload.data(), static_cast<DWORD>(payload.size()));
    if (err != NO_ERROR) {
        throw std::runtime_error("Failed to send CheckIn: " + std::to_string(err));
    }

    // Receive CheckIn response
    std::vector<uint8_t> recv_buffer(4096);
    DWORD bytes_read = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE buffer_type;

    err = WinHttpWebSocketReceive(h_websocket_, recv_buffer.data(),
                                   static_cast<DWORD>(recv_buffer.size()),
                                   &bytes_read, &buffer_type);
    if (err != NO_ERROR) {
        throw std::runtime_error("Failed to receive CheckIn response: " + std::to_string(err));
    }

    recv_buffer.resize(bytes_read);
    auto response_msgs = deserialize_messages(encryption_key_, recv_buffer);

    if (response_msgs.empty()) {
        throw std::runtime_error("Empty response from server");
    }

    auto* check_in_response = std::get_if<CheckInMessage>(&response_msgs[0]);
    if (!check_in_response) {
        throw std::runtime_error("Expected CheckInMessage from server");
    }

    messenger_id_ = check_in_response->messenger_id;
    std::cout << "[+] Connected with Messenger ID: " << messenger_id_ << std::endl;

    // Start send/receive threads
    std::thread(&WebSocketMessengerClient::send_messages, this).detach();
    receive_messages(); // Block on receive loop
}

void WebSocketMessengerClient::receive_messages() {
    std::vector<uint8_t> message_buffer;
    std::vector<uint8_t> recv_buffer(4096);

    while (true) {
        DWORD bytes_read = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE buffer_type;

        DWORD err = WinHttpWebSocketReceive(h_websocket_, recv_buffer.data(),
                                             static_cast<DWORD>(recv_buffer.size()),
                                             &bytes_read, &buffer_type);
        if (err != NO_ERROR) {
            std::cerr << "[!] WebSocket receive error: " << err << std::endl;
            break;
        }

        if (buffer_type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            std::cout << "[*] WebSocket connection closed by server" << std::endl;
            break;
        }

        message_buffer.insert(message_buffer.end(), recv_buffer.begin(), recv_buffer.begin() + bytes_read);

        // Binary message complete (not a fragment)
        if (buffer_type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) {
            try {
                auto messages = deserialize_messages(encryption_key_, message_buffer);
                for (const auto& msg : messages) {
                    std::thread([this, msg]() { handle_message(msg); }).detach();
                }
            } catch (const std::exception& ex) {
                std::cerr << "[!] Error parsing message: " << ex.what() << std::endl;
            }
            message_buffer.clear();
        }
        // If it's a BINARY_FRAGMENT, keep accumulating
    }
}

void WebSocketMessengerClient::send_messages() {
    while (true) {
        {
            std::lock_guard<std::mutex> lock(downstream_mutex_);
            if (downstream_messages_.empty()) {
                // Nothing to send, sleep briefly
            } else {
                std::vector<Message> msgs;
                msgs.push_back(Message{CheckInMessage{messenger_id_}});

                while (!downstream_messages_.empty()) {
                    msgs.push_back(downstream_messages_.front());
                    downstream_messages_.pop();
                }

                auto payload = serialize_messages(encryption_key_, msgs);

                DWORD err = WinHttpWebSocketSend(h_websocket_,
                    WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                    payload.data(), static_cast<DWORD>(payload.size()));
                if (err != NO_ERROR) {
                    std::cerr << "[!] WebSocket send error: " << err << std::endl;
                    break;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void WebSocketMessengerClient::send_downstream_message(const Message& message) {
    std::lock_guard<std::mutex> lock(downstream_mutex_);
    downstream_messages_.push(message);
}

void WebSocketMessengerClient::handle_message(const Message& message) {
    if (auto* cim = std::get_if<CheckInMessage>(&message)) {
        messenger_id_ = cim->messenger_id;
    } else {
        MessengerClient::handle_message(message);
    }
}

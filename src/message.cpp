#include "message.h"
#include "crypto.h"

#include <stdexcept>
#include <cstring>

// Base64 encode/decode helpers
static const std::string BASE64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string result;
    int val = 0;
    int valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(BASE64_CHARS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        result.push_back(BASE64_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (result.size() % 4) {
        result.push_back('=');
    }
    return result;
}

static std::vector<uint8_t> base64_decode(const std::string& encoded) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) {
        T[BASE64_CHARS[i]] = i;
    }

    std::vector<uint8_t> result;
    int val = 0;
    int valb = -8;
    for (char c : encoded) {
        if (T[static_cast<unsigned char>(c)] == -1) break;
        val = (val << 6) + T[static_cast<unsigned char>(c)];
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return result;
}

// MessageParser

std::pair<uint32_t, std::vector<uint8_t>> MessageParser::read_uint32(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        throw std::runtime_error("Not enough bytes to read a 32-bit value.");
    }

    uint32_t value = (static_cast<uint32_t>(data[0]) << 24) |
                     (static_cast<uint32_t>(data[1]) << 16) |
                     (static_cast<uint32_t>(data[2]) << 8)  |
                     (static_cast<uint32_t>(data[3]));

    std::vector<uint8_t> remainder(data.begin() + 4, data.end());
    return {value, remainder};
}

std::pair<std::string, std::vector<uint8_t>> MessageParser::read_string(const std::vector<uint8_t>& data) {
    auto [length, remainder] = read_uint32(data);

    if (remainder.size() < length) {
        throw std::runtime_error("Not enough bytes to read string of length " + std::to_string(length));
    }

    std::string s(remainder.begin(), remainder.begin() + length);
    std::vector<uint8_t> leftover(remainder.begin() + length, remainder.end());

    return {s, leftover};
}

CheckInMessage MessageParser::parse_check_in(const std::vector<uint8_t>& value) {
    auto [messenger_id, _] = read_string(value);
    return CheckInMessage{messenger_id};
}

InitiateForwarderClientReq MessageParser::parse_initiate_forwarder_client_req(const std::vector<uint8_t>& value) {
    auto [forwarder_client_id, r1] = read_string(value);
    auto [ip_address, r2] = read_string(r1);
    auto [port, r3] = read_uint32(r2);

    return InitiateForwarderClientReq{forwarder_client_id, ip_address, port};
}

InitiateForwarderClientRep MessageParser::parse_initiate_forwarder_client_rep(const std::vector<uint8_t>& value) {
    auto [forwarder_client_id, r1] = read_string(value);
    auto [bind_address, r2] = read_string(r1);
    auto [bind_port, r3] = read_uint32(r2);
    auto [address_type, r4] = read_uint32(r3);
    auto [reason, r5] = read_uint32(r4);

    return InitiateForwarderClientRep{forwarder_client_id, bind_address, bind_port, address_type, reason};
}

SendDataMessage MessageParser::parse_send_data(const std::vector<uint8_t>& value) {
    auto [forwarder_client_id, r1] = read_string(value);
    auto [encoded_data, r2] = read_string(r1);

    std::vector<uint8_t> raw_data = base64_decode(encoded_data);
    return SendDataMessage{forwarder_client_id, raw_data};
}

std::pair<std::vector<uint8_t>, Message> MessageParser::deserialize_message(
    const std::vector<uint8_t>& encryption_key,
    const std::vector<uint8_t>& raw_data
) {
    auto [message_type, data_after_type] = read_uint32(raw_data);
    auto [message_length, data_after_length] = read_uint32(data_after_type);

    int payload_len = static_cast<int>(message_length) - 8;
    if (static_cast<int>(data_after_length.size()) < payload_len) {
        throw std::runtime_error("Not enough bytes in data for the payload.");
    }

    std::vector<uint8_t> payload(data_after_length.begin(), data_after_length.begin() + payload_len);
    std::vector<uint8_t> leftover(data_after_length.begin() + payload_len, data_after_length.end());

    Message parsed_msg;

    switch (static_cast<MessageType>(message_type)) {
        case MessageType::INIT_FWD_REQ: {
            auto decrypted = Crypto::decrypt(encryption_key, payload);
            parsed_msg = parse_initiate_forwarder_client_req(decrypted);
            break;
        }
        case MessageType::INIT_FWD_REP: {
            auto decrypted = Crypto::decrypt(encryption_key, payload);
            parsed_msg = parse_initiate_forwarder_client_rep(decrypted);
            break;
        }
        case MessageType::SEND_DATA: {
            auto decrypted = Crypto::decrypt(encryption_key, payload);
            parsed_msg = parse_send_data(decrypted);
            break;
        }
        case MessageType::CHECK_IN: {
            parsed_msg = parse_check_in(payload);
            break;
        }
        default:
            throw std::runtime_error("Unknown message type: " + std::to_string(message_type));
    }

    return {leftover, parsed_msg};
}

// MessageBuilder

void MessageBuilder::write_uint32(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

std::vector<uint8_t> MessageBuilder::combine(const std::vector<std::vector<uint8_t>>& arrays) {
    std::vector<uint8_t> result;
    size_t total = 0;
    for (const auto& arr : arrays) {
        total += arr.size();
    }
    result.reserve(total);
    for (const auto& arr : arrays) {
        result.insert(result.end(), arr.begin(), arr.end());
    }
    return result;
}

std::vector<uint8_t> MessageBuilder::build_message(uint32_t message_type, const std::vector<uint8_t>& payload) {
    uint32_t message_length = 8 + static_cast<uint32_t>(payload.size());

    std::vector<uint8_t> header;
    header.reserve(8);
    write_uint32(header, message_type);
    write_uint32(header, message_length);

    return combine({header, payload});
}

std::vector<uint8_t> MessageBuilder::build_string(const std::string& value) {
    std::vector<uint8_t> encoded(value.begin(), value.end());
    std::vector<uint8_t> length_bytes;
    write_uint32(length_bytes, static_cast<uint32_t>(encoded.size()));

    return combine({length_bytes, encoded});
}

std::vector<uint8_t> MessageBuilder::build_check_in_message(const std::string& messenger_id) {
    return build_string(messenger_id);
}

std::vector<uint8_t> MessageBuilder::build_initiate_forwarder_client_req(
    const std::string& forwarder_client_id,
    const std::string& ip_address,
    uint32_t port
) {
    auto part1 = build_string(forwarder_client_id);
    auto part2 = build_string(ip_address);

    std::vector<uint8_t> part3;
    write_uint32(part3, port);

    return combine({part1, part2, part3});
}

std::vector<uint8_t> MessageBuilder::build_initiate_forwarder_client_rep(
    const std::string& forwarder_client_id,
    const std::string& bind_address,
    uint32_t bind_port,
    uint32_t address_type,
    uint32_t reason
) {
    auto part1 = build_string(forwarder_client_id);
    auto part2 = build_string(bind_address);

    std::vector<uint8_t> part3;
    write_uint32(part3, bind_port);
    write_uint32(part3, address_type);
    write_uint32(part3, reason);

    return combine({part1, part2, part3});
}

std::vector<uint8_t> MessageBuilder::build_send_data(
    const std::string& forwarder_client_id,
    const std::vector<uint8_t>& data
) {
    auto part1 = build_string(forwarder_client_id);
    std::string encoded_data = base64_encode(data);
    auto part2 = build_string(encoded_data);

    return combine({part1, part2});
}

std::vector<uint8_t> MessageBuilder::serialize_message(
    const std::vector<uint8_t>& encryption_key,
    const Message& msg
) {
    uint32_t message_type;
    std::vector<uint8_t> payload;

    if (auto* req = std::get_if<InitiateForwarderClientReq>(&msg)) {
        message_type = static_cast<uint32_t>(MessageType::INIT_FWD_REQ);
        auto plain = build_initiate_forwarder_client_req(
            req->forwarder_client_id, req->ip_address, req->port
        );
        payload = Crypto::encrypt(encryption_key, plain);
    } else if (auto* rep = std::get_if<InitiateForwarderClientRep>(&msg)) {
        message_type = static_cast<uint32_t>(MessageType::INIT_FWD_REP);
        auto plain = build_initiate_forwarder_client_rep(
            rep->forwarder_client_id, rep->bind_address,
            rep->bind_port, rep->address_type, rep->reason
        );
        payload = Crypto::encrypt(encryption_key, plain);
    } else if (auto* sdm = std::get_if<SendDataMessage>(&msg)) {
        message_type = static_cast<uint32_t>(MessageType::SEND_DATA);
        auto plain = build_send_data(sdm->forwarder_client_id, sdm->data);
        payload = Crypto::encrypt(encryption_key, plain);
    } else if (auto* cim = std::get_if<CheckInMessage>(&msg)) {
        message_type = static_cast<uint32_t>(MessageType::CHECK_IN);
        payload = build_check_in_message(cim->messenger_id);
    } else {
        throw std::runtime_error("Unknown message type");
    }

    return build_message(message_type, payload);
}

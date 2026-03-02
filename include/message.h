#ifndef MESSAGE_H
#define MESSAGE_H

#include <cstdint>
#include <string>
#include <vector>
#include <variant>

// Message type constants
enum class MessageType : uint32_t {
    INIT_FWD_REQ = 0x01,
    INIT_FWD_REP = 0x02,
    SEND_DATA    = 0x03,
    CHECK_IN     = 0x04,
};

struct CheckInMessage {
    std::string messenger_id;
};

struct InitiateForwarderClientReq {
    std::string forwarder_client_id;
    std::string ip_address;
    uint32_t port;
};

struct InitiateForwarderClientRep {
    std::string forwarder_client_id;
    std::string bind_address;
    uint32_t bind_port;
    uint32_t address_type;
    uint32_t reason;
};

struct SendDataMessage {
    std::string forwarder_client_id;
    std::vector<uint8_t> data;
};

using Message = std::variant<
    CheckInMessage,
    InitiateForwarderClientReq,
    InitiateForwarderClientRep,
    SendDataMessage
>;

class MessageParser {
public:
    static std::pair<uint32_t, std::vector<uint8_t>> read_uint32(const std::vector<uint8_t>& data);
    static std::pair<std::string, std::vector<uint8_t>> read_string(const std::vector<uint8_t>& data);

    static CheckInMessage parse_check_in(const std::vector<uint8_t>& value);
    static InitiateForwarderClientReq parse_initiate_forwarder_client_req(const std::vector<uint8_t>& value);
    static InitiateForwarderClientRep parse_initiate_forwarder_client_rep(const std::vector<uint8_t>& value);
    static SendDataMessage parse_send_data(const std::vector<uint8_t>& value);

    static std::pair<std::vector<uint8_t>, Message> deserialize_message(
        const std::vector<uint8_t>& encryption_key,
        const std::vector<uint8_t>& raw_data
    );
};

class MessageBuilder {
public:
    static std::vector<uint8_t> build_message(uint32_t message_type, const std::vector<uint8_t>& payload);
    static std::vector<uint8_t> build_string(const std::string& value);

    static std::vector<uint8_t> build_check_in_message(const std::string& messenger_id);
    static std::vector<uint8_t> build_initiate_forwarder_client_req(
        const std::string& forwarder_client_id,
        const std::string& ip_address,
        uint32_t port
    );
    static std::vector<uint8_t> build_initiate_forwarder_client_rep(
        const std::string& forwarder_client_id,
        const std::string& bind_address,
        uint32_t bind_port,
        uint32_t address_type,
        uint32_t reason
    );
    static std::vector<uint8_t> build_send_data(
        const std::string& forwarder_client_id,
        const std::vector<uint8_t>& data
    );

    static std::vector<uint8_t> serialize_message(
        const std::vector<uint8_t>& encryption_key,
        const Message& msg
    );

private:
    static void write_uint32(std::vector<uint8_t>& buffer, uint32_t value);
    static std::vector<uint8_t> combine(const std::vector<std::vector<uint8_t>>& arrays);
};

#endif // MESSAGE_H

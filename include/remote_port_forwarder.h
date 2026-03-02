#ifndef REMOTE_PORT_FORWARDER_H
#define REMOTE_PORT_FORWARDER_H

#include "messenger_client.h"

#include <string>

class RemotePortForwarder {
public:
    RemotePortForwarder(MessengerClient& messenger, const std::string& config);

    void start();

private:
    void handle_client(int client_fd);
    void parse_config(const std::string& config);

    MessengerClient& messenger_;
    std::string listening_host_;
    int listening_port_;
    std::string destination_host_;
    int destination_port_;
};

#endif // REMOTE_PORT_FORWARDER_H

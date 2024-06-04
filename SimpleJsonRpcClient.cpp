#include "SimpleJsonRpcClient.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <memory.h>
#include <csignal>

extern volatile sig_atomic_t sigint_received;

SimpleJsonRpcClient::SimpleJsonRpcClient()
    : host_(""), port_(0), is_connected(false), nBytesToRead(0) {
        memset(this->buffer, 0, sizeof(this->buffer));
}

SimpleJsonRpcClient::~SimpleJsonRpcClient() {
    this->stop();
}

bool SimpleJsonRpcClient::connect(const std::string& host, int port){
    return createSocket(host, port);
}

bool SimpleJsonRpcClient::connected(){
    return this->is_connected;
}

void SimpleJsonRpcClient::stop() {
    close(this->socket_);
    this->is_connected = false;
}

bool SimpleJsonRpcClient::print(const std::string& params) {
    std::lock_guard<std::mutex> lock(this->mutex_);
    return send(socket_, params.c_str(), params.length(), 0) >= 0;
}

std::string SimpleJsonRpcClient::readStringUntil(char delimiter) {
    std::string data;
  
    while (!sigint_received) {
        for (int i = 0; i < this->nBytesToRead; ++i) {
            if (this->buffer[i] == delimiter) {
                strcpy(this->buffer, &(this->buffer[i+1]));
                this->nBytesToRead -= i+1;
                return data;
            }
            data += this->buffer[i];
        }

        this->nBytesToRead = recv(socket_, this->buffer, sizeof(this->buffer), 0);
        if (this->nBytesToRead <= 0) {
            this->stop();
            break;
        }
        #ifdef VERBOSE
        std::cout << "Received " << this->nBytesToRead << " bytes -> " << std::string(this->buffer, this->nBytesToRead-1) << std::endl;
        #endif
    }

    return data;
}

bool SimpleJsonRpcClient::createSocket(const std::string& host, int port) {
    this->host_ = host;
    this->port_ = port;

    struct addrinfo hints, *server_info, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int status = getaddrinfo(host.c_str(), port_str, &hints, &server_info);
    if (status != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        return false;
    }

    // Loop through all the results and connect to the first we can
    for (p = server_info; p != NULL; p = p->ai_next) {
        this->socket_ = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (this->socket_ == -1) {
            continue;
        }

        if (::connect(this->socket_, p->ai_addr, p->ai_addrlen) == -1) {
            close(this->socket_);
            continue;
        }

        break; // Connection successful
    }

    if (p == NULL) {
        std::cerr << "Failed to connect to " << host << ":" << port << std::endl;
        return false;
    }

    freeaddrinfo(server_info); // All done with this structure

    this->is_connected = true;
    this->nBytesToRead = 0;
    return true;
}



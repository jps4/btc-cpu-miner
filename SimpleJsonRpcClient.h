#ifndef SIMPLE_JSON_RPC_CLIENT_H
#define SIMPLE_JSON_RPC_CLIENT_H

#include <iostream>
#include <string>
#include <mutex>

class SimpleJsonRpcClient {
public:
    SimpleJsonRpcClient();
    ~SimpleJsonRpcClient();

    bool connect(const std::string& host, int port);
    void stop();
    bool print(const std::string& params);
    std::string readStringUntil(char delimiter);
    bool connected();

private:
    bool createSocket(const std::string& host, int port);

    std::string host_;
    int port_;
    int socket_;
    bool is_connected;

    char buffer[4096];
    int nBytesToRead;

    std::mutex mutex_;
};

#endif
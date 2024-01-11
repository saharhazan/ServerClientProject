// Name: Sahar Hazan
// ID: 316495092

#include <iostream>
#include <stdexcept>
#include <winsock2.h>
#include "Client.h"
#include "FileHandler.h"
#include <WS2tcpip.h>
int main() {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;

    try {
        Client handler;
        FileHandler fHandler;
        std::string ip_addr;
        uint16_t port;
        char uuid[CLIENT_ID_SIZE] = { 0 };
        char username[USER_LENGTH] = { 0 };
        char AESEncrypted[ENC_AES_LEN] = { 0 };
        bool isNewUser;

        // Initialize Winsock
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup Failed");
        }

        // Get server information from the Client object
        if (!handler.getServerInfo(ip_addr, port)) {
            throw std::runtime_error("Failed to get server information");
        }

        // Create a socket
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket");
        }

        // Configure the server address
        struct sockaddr_in sa = { 0 };
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, ip_addr.c_str(), &sa.sin_addr);

        // Determine user status and login/register as needed
        if (fHandler.fileExists(ME_INFO)) {
            isNewUser = handler.loginUser(sock, &sa, username, uuid, AESEncrypted);
        }
        else if (fHandler.fileExists(TRANSFER_INFO)) {
            isNewUser = handler.createNewUser(sock, &sa, uuid);
        }
        else {
            throw std::runtime_error("User status could not be determined");
        }

        // Create a socket
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket");
        }
        // Send a file using the handler
        handler.sendFile(sock, &sa, uuid, AESEncrypted, isNewUser);

        // Cleanup
        closesocket(sock);
        WSACleanup();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
        WSACleanup();
        return 1;
    }

    return 0;
}
# C++ and Python Project: Encrypted File Transfer Server & Client
## About
This project involves a Python-based server and a C++-based client, designed for encrypted file transfer. The server manages user registrations and file transfers, while the client handles secure communication with the server.

## Project Structure
### Server (Python)
server.py: Manages user registrations and file transfer requests.
FileHandler.py: Handles file operations like reading, writing, and creating directories.  
constants.py: Defines constants used across the server application.
crc.py: Implements CRC (Cyclic Redundancy Check) for data integrity verification.  
database.py: Manages database operations, including user and file data storage.  
encryptor.py: Handles the encryption and decryption processes.
main.py: The entry point of the server application, orchestrating various components.  
protocol.py: Defines the communication protocol between the server and client.  
utils.py: Provides utility functions used throughout the application.
### Client (C++)
Client.cpp: The main client application responsible for file encryption and transfer.  
ClientHandler.cpp: Manages client-side logic and communication protocols, ensuring secure data transfer.  
AESWrapper.h/cpp: Provides AES encryption functionality for securing file contents.    
Base64Wrapper.h/cpp: Handles encoding and decoding data in Base64 format. 
CRC.h/cpp: Implements cyclic redundancy checks for data integrity verification. 
Client.h: Contains key definitions, constants, and utility functions used throughout the client application.

#### Key Variables in Client.h

| Variable Name       | Size/Type          | Description                                    |
|---------------------|--------------------|------------------------------------------------|
| `PACKET_SIZE`       | Macro (1024)       | Defines the size of data packets.              |
| `USER_LENGTH`       | Macro (255)        | Maximum length for user information.           |
| `ME_INFO`           | Macro (file path)  | Path to the client's information file.         |
| `TRANSFER_INFO`     | Macro (file path)  | Path to the file transfer information file.    |
| `PRIV_KEY`          | Macro (file path)  | Path to the private key file.                  |
| `PUB_KEY_LEN`       | Macro (160)        | Length of the public key.                      |
| `AES_KEY_LEN`       | Macro (16)         | Length of the AES key.                         |
| `AES_BLOCK_SIZE`    | Macro (16)         | AES encryption block size.                     |
| `CLIENT_ID_SIZE`    | Macro (16)         | Size of the client ID.                         |
| `MAX_CHAR_FILE_LEN` | Macro (255)        | Maximum character length for file names.       |
| `TRANSFER_LINES`    | Macro (3)          | Number of lines in the transfer info file.     |
| `PRIV_KEY_LINES`    | Macro (12)         | Number of lines in the private key file.       |
| `ENC_AES_LEN`       | Macro (128)        | Length of the encrypted AES key.               |
| `MAX_TRIES`         | Macro (3)          | Maximum number of retry attempts.              |
| `AESKey`            | Array (16 bytes)   | Array to store the AES key.                    |
| `uuid`              | Array (16 bytes)   | Array to store the client's UUID.              |

These variables are essential for the client's configuration and operation within the file transfer system.


Additional C++ files for encryption, file handling, and network communication.

### Server Architecture
Multi-threaded or selector-based handling of multiple users.
SQL database for storing user and file data.
Tables for clients and files with specific fields (ID, Name, PublicKey, LastSeen, AES key, etc.).

Data security with encryption using the Cipher.Crypto package.

### Client Architecture
Batch mode operation with fixed order of tasks.  
Encryption using the CryptoPP package.  
Client version management and error handling mechanisms.     
### Protocol        
Binary protocol over TCP.          
Client-server requests and responses with specific fields (Client ID, Version, Request Code, etc.).    
Detailed request and response structures for various operations like registration, file transfer, and encryption key exchange.
### Encryption
Symmetric encryption using AES-CBC for message encryption.
Asymmetric encryption using RSA for key exchange.  
### Development Emphasis
Modular development with continuous testing.
Object-oriented programming principles.
Proper documentation and meaningful naming of variables and functions.

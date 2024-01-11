// Name: Sahar Hazan
// ID: 316495092

#include "Client.h"

// Sends the RSA Public Key and inserts the received AES key into AESKey. 
bool Client::sendPubKey(const SOCKET& sock, sockaddr_in* sa, unsigned char* AESKey, char* uuid) const
{
	RSAPrivateWrapper rsapriv;
	std::string pubkey = rsapriv.getPublicKey();
	RSAPublicWrapper rsapub(pubkey);
	FileHandler fHandler;
	std::fstream newFile;
	std::fstream privFile;


	try {
		int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa));
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}

	std::string username;
	if (fHandler.fileExists(ME_INFO)) {
		if (!fHandler.initializeFile(ME_INFO, newFile, false))
			return false;
		std::getline(newFile, username);
		fHandler.finalizeFile(newFile);
	}
	else if (fHandler.fileExists(TRANSFER_INFO)) {
		if (!fHandler.initializeFile(TRANSFER_INFO, newFile, false))
			return false;
		std::getline(newFile, username);
		std::getline(newFile, username); // Second line.
		fHandler.finalizeFile(newFile);
	}
	else {
		std::cerr << "Error: Transfer and info files do not exist. " << std::endl;
		return false;
	}

	std::string privkey = rsapriv.getPrivateKey();
	std::string encoded_privkey = Base64Wrapper::encode(privkey);


	if (!fHandler.initializeFile(ME_INFO, newFile, true))
		return false;

	fHandler.writeToFile(newFile, "\n", strlen("\n"));
	fHandler.writeToFile(newFile, encoded_privkey.c_str(), encoded_privkey.length());
	fHandler.finalizeFile(newFile);

	// Open or create the file "priv.key" for writing
	if (!fHandler.openAndOverwriteFile(PRIV_KEY, privFile))
		return false;

	// Write the private key to "priv.key"
	fHandler.writeToFile(privFile, encoded_privkey.c_str(), encoded_privkey.length());

	// Close the file "priv.key"
	fHandler.finalizeFile(privFile);

	Request req;
	char requestBuffer[PACKET_SIZE] = { 0 };
	if (username.length() >= USER_LENGTH) {
		std::cout << "Username doesn't meet the length criteria. " << std::endl;
		return false;
	}

	req._request.URequestHeader.SRequestHeader.payload_size = username.length() + 1 + PUB_KEY_LEN;
	req._request.payload = new char[req._request.URequestHeader.SRequestHeader.payload_size];
	memcpy(req._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
	memcpy(req._request.payload, username.c_str(), username.length() + 1);
	memcpy(req._request.payload + username.length() + 1, pubkey.c_str(), PUB_KEY_LEN);
	std::cout << "Sending the following pubkey: \n" << pubkey.c_str() << "." << std::endl;
	req._request.URequestHeader.SRequestHeader.code = PUB_KEY_SEND;

	req.packRequest(requestBuffer);
	send(sock, requestBuffer, PACKET_SIZE, 0);

	char buffer[PACKET_SIZE] = { 0 };
	recv(sock, buffer, PACKET_SIZE, 0);

	Response res;
	res.unpackResponse(buffer);
	if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
		std::cout << "Error: Server failed to receive Public Key. " << std::endl;
		return false;
	}
	else if (res._response.UResponseHeader.SResponseHeader.code == PUB_KEY_RECEVIED) {
		RSAPrivateWrapper rsapriv_other(rsapriv.getPrivateKey());
		char encryptedAESKey[ENC_AES_LEN] = { 0 };

		memcpy(encryptedAESKey, res._response.payload + CLIENT_ID_SIZE, ENC_AES_LEN);
		std::string decryptedAESKey = rsapriv_other.decrypt(encryptedAESKey, ENC_AES_LEN);
		memcpy(AESKey, decryptedAESKey.c_str(), AES_KEY_LEN);
		std::cout << "The AESKey has been recieved and decrypred successfully." << std::endl;
		return true;
	}
	return false;
}

// Places the server info into the received variables. Returns true upon success and false upon failure. 
bool Client::getServerInfo(std::string& ip_address, uint16_t& port) const
{
	FileHandler fHandler;
	std::fstream newFile;
	std::string fullLine;
	if (!fHandler.fileExists(TRANSFER_INFO)) {
		std::cerr << "Error: Transfer file doesn't exist. " << std::endl;
		return false;
	}
	if (!fHandler.initializeFile(TRANSFER_INFO, newFile, false))
		return false;
	
	if (!std::getline(newFile, fullLine)) {
		std::cerr << "Error reading from transfer file. " << std::endl;
		return false;
	}
	fHandler.finalizeFile(newFile);

	size_t pos = fullLine.find(":");
	ip_address = fullLine.substr(0, pos);
	fullLine.erase(0, pos + 1);

	int tmp = std::stoi(fullLine);
	if (tmp <= static_cast<int>(UINT16_MAX) && tmp >= 0)
		port = static_cast<uint16_t>(tmp);
	else {
		std::cerr << "Error: Port is invalid." << std::endl;
		return false;
	}
	return true;
}

bool Client::createNewUser(const SOCKET& socket, struct sockaddr_in* serverAddr, char* clientUuid) const
{
	FileHandler fileOp;
	std::fstream userFile;
	try {
		int connectionResult = connect(socket, (struct sockaddr*)serverAddr, sizeof(*serverAddr)); // Establishing a connection with the server
	}
	catch (std::exception& exception) {
		std::cerr << "Connection error: " << exception.what() << std::endl;
		return false;
	}

	std::string userID;
	std::string extractedUuid;
	bool uuidFound = false; // Indicator for UUID presence in ME_INFO

	// Handling the existence of ME_INFO for user login
	if (fileOp.fileExists(ME_INFO)) {
		if (!fileOp.initializeFile(ME_INFO, userFile, false))
			return false;
		std::getline(userFile, userID);
		if (std::getline(userFile, extractedUuid)) {
			uuidFound = true; // Successfully retrieved UUID
		}
		fileOp.finalizeFile(userFile);
	}
	else if (fileOp.fileExists(TRANSFER_INFO)) {
		if (!fileOp.initializeFile(TRANSFER_INFO, userFile, false))
			return false;
		std::getline(userFile, userID);
		std::getline(userFile, userID); // Read second line for userID
		fileOp.finalizeFile(userFile);
	}
	else {
		std::cerr << "Critical Error: Missing necessary files." << std::endl;
		return false;
	}

	Request req;
	char reqBuffer[PACKET_SIZE] = { 0 };
	if (userID.size() >= USER_LENGTH) {
		std::cerr << "Invalid username length." << std::endl;
		return false;
	}
	req._request.URequestHeader.SRequestHeader.payload_size = userID.length() + 1;
	req._request.payload = new char[req._request.URequestHeader.SRequestHeader.payload_size];
	memcpy(req._request.payload, userID.c_str(), userID.length() + 1);
	req._request.URequestHeader.SRequestHeader.code = REGISTER_REQUEST;

	req.packRequest(reqBuffer);
	std::cout << "Attempting to register user: " << userID << std::endl;
	send(socket, reqBuffer, PACKET_SIZE, 0);

	char responseBuffer[PACKET_SIZE] = { 0 };
	recv(socket, responseBuffer, PACKET_SIZE, 0);

	Response res;
	res.unpackResponse(responseBuffer);
	if (res._response.UResponseHeader.SResponseHeader.code == REGISTER_ERROR) {
		std::cerr << "Registration failed: User already registered." << std::endl;
		exit(1);
	}
	else if (res._response.UResponseHeader.SResponseHeader.code == REGISTER_SUCCESS) {
		updateUserInfo(fileOp, userFile, userID, res, uuidFound);
		std::cout << "User information updated successfully." << std::endl;
		memcpy(clientUuid, res._response.payload, CLIENT_ID_SIZE);
		closesocket(socket);
		return true;
	}
	else if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
		std::cerr << "Registration failed: Unknown error." << std::endl;
		exit(1);
	}
	return false;
}

void Client::updateUserInfo(FileHandler& fileOp, std::fstream& userFile, const std::string& userID, const Response& res, bool uuidFound) const {
	bool fileExists = fileOp.fileExists(ME_INFO);

	// Initialize ME_INFO file for writing
	if (!fileOp.initializeFile(ME_INFO, userFile, true)) {
		return;
	}

	if (fileExists) {
		if (!uuidFound) {
			// UUID not found, write directly
			fileOp.writeToFile(userFile, userID.c_str(), userID.length());
			fileOp.writeToFile(userFile, "\n", strlen("\n"));
			fileOp.hexifyToFile(userFile, res._response.payload, res._response.UResponseHeader.SResponseHeader.payload_size);
		}
		else {
			// UUID found, close and reopen for overwrite
			fileOp.finalizeFile(userFile);

			if (!fileOp.openAndOverwriteFile(ME_INFO, userFile)) {
				return;
			}
			fileOp.writeToFile(userFile, userID.c_str(), userID.length());
			fileOp.writeToFile(userFile, "\n", strlen("\n"));
			fileOp.hexifyToFile(userFile, res._response.payload, res._response.UResponseHeader.SResponseHeader.payload_size);
		}
	}
	else {
		// File does not exist, write new content
		fileOp.writeToFile(userFile, userID.c_str(), userID.length());
		fileOp.writeToFile(userFile, "\n", strlen("\n"));
		fileOp.hexifyToFile(userFile, res._response.payload, res._response.UResponseHeader.SResponseHeader.payload_size);
	}

	fileOp.finalizeFile(userFile);
}

bool Client::decryptAESKey(const char* uuid, const char* encryptedAESKey, unsigned char* AESKey) const
{
	FileHandler fHandler;
	RSAPrivateWrapper rsapriv2;
	std::fstream privFile;

	// Open the priv.key file for reading the stored key in there
	if (!fHandler.initializeFile(PRIV_KEY, privFile, false)) {
		std::cerr << "Error: Failed to open priv.key file." << std::endl;
		return false;
	}

	// Read the encoded private key from priv.key
	std::string encoded_privkey= "";
	std::string temp_privkey_line = "";
	for (int i = 0; i < PRIV_KEY_LINES; i++) {
		std::getline(privFile, temp_privkey_line);
		encoded_privkey += temp_privkey_line;
	}
	fHandler.finalizeFile(privFile);

	std::string privkey = Base64Wrapper::decode(encoded_privkey);
	RSAPrivateWrapper rsapriv(privkey);
	std::cout << "Got private key from priv.key." << std::endl;

	// Decrypt the encrypted AES key using the private key
	std::string decryptedAESKey = {0};
	try {
		decryptedAESKey = rsapriv.decrypt(encryptedAESKey, ENC_AES_LEN);
	}
	catch (std::exception& e) {
		std::cerr << "Error - Failed to get the user's private key. Please check if your priv.key matches the user's actual private key. " << std::endl;
		exit(1);
	}
	
	// Copy the decrypted AES key to AESKey buffer
	memcpy(AESKey, decryptedAESKey.c_str(), AES_KEY_LEN);
	std::cerr << "Decrypted the AESKey successfully for the connected user." << std::endl;
	return true;
}

// The function handles sending a file over to the server. 
bool Client::sendFile(const SOCKET& sock, sockaddr_in* sa, char* uuid, char* EncryptedAESKey,bool isNewUser) const
{
	unsigned char AESKey[AES_KEY_LEN] = { 0 };
	if (isNewUser){
		if (!sendPubKey(sock, sa, AESKey, uuid))
			return false;
			}
	else {
		if (!decryptAESKey(uuid, EncryptedAESKey, AESKey))
			return false;
		try {
			int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa)); // Connection to the server 
		}
		catch (std::exception& e) {
			std::cerr << "Exception: " << e.what() << std::endl;
			return false;
		}
	}
	FileHandler fHandler;
	std::fstream requestedFile;
	char requestBuffer[PACKET_SIZE] = { 0 };
	
	if (!fHandler.fileExists(TRANSFER_INFO)) {
		std::cerr << "Error: Transfer file doesn't exist. Cannot retrieve file name. " << std::endl;
		closesocket(sock);
		return false;
	}
	if (!fHandler.initializeFile(TRANSFER_INFO, requestedFile, false)) {
		std::cerr << "Error: Failed to open TRANSFER INFO file." << std::endl;
		closesocket(sock);
		return false;
	}
	
	std::string filename;

	for (int i = 0; i < TRANSFER_LINES; i++)
		std::getline(requestedFile, filename);
	
	fHandler.finalizeFile(requestedFile);
	
	if (filename.length() > MAX_CHAR_FILE_LEN) {
		std::cerr << "Error - Filename length too long. " << std::endl;
		closesocket(sock);
		return false;
	}

	if (!fHandler.fileExists(filename)) {
		std::cerr << "Error - File: "<< filename<<", doesn't exist. " << std::endl;
		closesocket(sock);
		return false;
	}

	std::cout << "Filename successfully found in transer_info. Preparing to send file." << std::endl;

	Request req;
	uint32_t fileSize = fHandler.retrieveFileSize(filename);
	uint32_t contentSize = fileSize + (AES_BLOCK_SIZE - fileSize % AES_BLOCK_SIZE); // After encryption
	req._request.URequestHeader.SRequestHeader.payload_size = contentSize + MAX_CHAR_FILE_LEN + sizeof(uint32_t);
	uint32_t payloadSize = req._request.URequestHeader.SRequestHeader.payload_size;
	req._request.payload = new char[payloadSize];
	memset(req._request.payload, 0, payloadSize);
	memcpy(req._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
	req._request.URequestHeader.SRequestHeader.code = FILE_SEND;

	uint32_t currPayload = payloadSize < PACKET_SIZE - req.offset() ? payloadSize : PACKET_SIZE - req.offset();

	char* payloadPtr = req._request.payload;
	memcpy(payloadPtr, &contentSize, sizeof(uint32_t));
	payloadPtr += sizeof(uint32_t);
	memcpy(payloadPtr, filename.c_str(), filename.length());
	payloadPtr += MAX_CHAR_FILE_LEN;
	
	// Read File into Payload
	std::string filepath = "./" + filename; // We assume the file is in current dir
	fHandler.openBinaryFile(filepath, requestedFile, false);
	fHandler.loadFromFile(requestedFile, payloadPtr, fileSize);
	fHandler.finalizeFile(requestedFile);


	// Calculate checksum of file before encryption
	CRC digest;
	digest.update((unsigned char*)payloadPtr, fileSize);
	uint32_t checksum = digest.digest();

	AESWrapper wrapper(AESKey, AES_KEY_LEN);
	std::string tmpEncryptedData = wrapper.encrypt(payloadPtr, fileSize);
	memcpy(payloadPtr, tmpEncryptedData.c_str(), tmpEncryptedData.length());	
	
	bool crc_confirmed = false;
	size_t tries = 0;

	while (tries < MAX_TRIES && !crc_confirmed) {
		req.packRequest(requestBuffer);
		send(sock, requestBuffer, PACKET_SIZE, 0); // 1028

		uint32_t sizeLeft = payloadSize - currPayload;
		payloadPtr = req._request.payload + currPayload;
		while (sizeLeft > 0) {
			memset(requestBuffer, 0, PACKET_SIZE);
			currPayload = sizeLeft < PACKET_SIZE ? sizeLeft : PACKET_SIZE;
			memcpy(requestBuffer, payloadPtr, currPayload);
			send(sock, requestBuffer, PACKET_SIZE, 0);

			sizeLeft -= currPayload;
			payloadPtr += currPayload;
		} // Finish sending file

		char buffer[PACKET_SIZE] = { 0 };
		recv(sock, buffer, PACKET_SIZE, 0); // Expecting Code 2103

		Response res;
		res.unpackResponse(buffer);
		if (res._response.UResponseHeader.SResponseHeader.code != FILE_OK_CRC) {
			std::cout << "Error: Server responded with an error. " << std::endl;
			closesocket(sock);
			return false;
		}

		std::cout << "Server received file: "<< filename << ", checking checksum.." << std::endl;

		uint32_t received_checksum;
		memcpy(&received_checksum, res._response.payload + sizeof(uint32_t) + MAX_CHAR_FILE_LEN, sizeof(uint32_t));

		if (checksum == received_checksum) {
			crc_confirmed = true;
			std::cout << "Checksum matches!" << std::endl;
		}
		else {
			tries++;
			std::cout << "Checksum does not match: " << tries << "/3" << " tries." << std::endl;
		}

		Request newReq;
		newReq._request.URequestHeader.SRequestHeader.code = crc_confirmed ? CRC_OK : CRC_INVALID_RETRY;
		if (tries == MAX_TRIES)
			newReq._request.URequestHeader.SRequestHeader.code = CRC_INVALID_EXIT;

		newReq._request.URequestHeader.SRequestHeader.payload_size = MAX_CHAR_FILE_LEN;
		newReq._request.payload = new char[MAX_CHAR_FILE_LEN];
		memcpy(newReq._request.payload, filename.c_str(), filename.length());
		memcpy(newReq._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
		memset(requestBuffer, 0, PACKET_SIZE);
		newReq.packRequest(requestBuffer);
		send(sock, requestBuffer, PACKET_SIZE, 0);
	}

	try {
		char buffer[PACKET_SIZE] = { 0 };
		recv(sock, buffer, PACKET_SIZE, 0); // Expecting Code 2104

		Response res;
		res.unpackResponse(buffer);
		if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
			std::cout << "Error: Server did not confirm receiving the message. " << std::endl;
			closesocket(sock);
			return false;
		}
		else if(res._response.UResponseHeader.SResponseHeader.code == MSG_RECEIVED){
			std::cout << "The file was successfully (and safely) uploaded to the server." << std::endl;
		}
	}
	catch (std::exception& e) {
		std::cerr << "Couldn't receive final answer. Exception: " << e.what() << std::endl;
		closesocket(sock);
		exit(1);
	}

	closesocket(sock);
	return true;
}

bool Client::loadClientInfo(char* username) const {
	FileHandler fHandler;
	std::fstream newFile;
	std::string usernameStr;


	// Check if 'me.info' exists and open it
	if (fHandler.fileExists(ME_INFO)) {
		std::cout << "Client - login opening me file" << std::endl;

		if (!fHandler.initializeFile(ME_INFO, newFile, false))
			return false;

		std::getline(newFile, usernameStr);
		memcpy(username, usernameStr.c_str(), USER_LENGTH);
		fHandler.finalizeFile(newFile);
	}
	else if (fHandler.fileExists(TRANSFER_INFO)) {
		if (!fHandler.initializeFile(TRANSFER_INFO, newFile, false))
			return false;
		std::getline(newFile, usernameStr);
		std::getline(newFile, usernameStr);
		memcpy(username, usernameStr.c_str(), USER_LENGTH);
		fHandler.finalizeFile(newFile);
	}

	else {
		std::cerr << "Error: Transfer.info and Me.info files do not exist. " << std::endl;
		return false;  // Return false if 'me.info' does not exist
	}

	return true;  // Return true if username was successfully loaded
}

bool Client::loginUser(const SOCKET& sock, struct sockaddr_in* sa, char* username, char* uuid, char* AESKey) const {
	if (!loadClientInfo(username)) {
		std::cerr << "Error: Failed to load client info." << std::endl;
	}

	try {
		int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa));
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}

	Request req;
	char requestBuffer[PACKET_SIZE] = { 0 };

	// Set the request header fields for a login request
	req._request.URequestHeader.SRequestHeader.payload_size = strlen(username)+1;  // +1 for the null terminator
	req._request.payload = new char[strlen(username)+1];  // +1 for the null terminator
	memcpy(req._request.payload, username, strlen(username)+1);  // +1 to include the null terminator
	req._request.URequestHeader.SRequestHeader.code = LOGIN_REQUEST;

	// Pack the request and send it
	req.packRequest(requestBuffer);
	send(sock, requestBuffer, PACKET_SIZE, 0);

	// Receive the server response
	char buffer[PACKET_SIZE] = { 0 };
	recv(sock, buffer, PACKET_SIZE, 0);

	Response res;
	res.unpackResponse(buffer);

	// Check for a successful login response code
 	if (res._response.UResponseHeader.SResponseHeader.code == LOGIN_SUCCESS) {
		std::cout << "Successfully logged in - " << username << std::endl;
		// Copy the encrypted AES key and the UUID from the response payload
		memcpy(uuid, res._response.payload, CLIENT_ID_SIZE);
		memcpy(AESKey, res._response.payload + CLIENT_ID_SIZE, ENC_AES_LEN);
		return false; // Return false, since the logged-in user is not new
	}

	else if (res._response.UResponseHeader.SResponseHeader.code == LOGIN_ERROR) {
		std::cout << "Failed to login, this user needs to be registered!" << std::endl;
		closesocket(sock);

		// Create a new socket
		SOCKET new_sock = socket(AF_INET, SOCK_STREAM, 0);
		if (new_sock == INVALID_SOCKET) {
			std::cerr << "Error: Unable to create socket." << std::endl;
			return false;
		}

		// Re-establish the connection
		int connRes = connect(new_sock, (struct sockaddr*)sa, sizeof(*sa));
		if (connRes == SOCKET_ERROR) {
			std::cerr << "Error: Unable to connect to server." << std::endl;
			closesocket(new_sock);
			return false;
		}

		if (createNewUser(new_sock, sa, uuid)) {
			std::cout << "The following user has registered successfully - "<< username << std::endl;
			return true;  // Return true as the user is now registered as a new user
		}
		else {
			std::cout << "Error: Failed to register user." << std::endl;
			return false;
		}
		return false;
	}

	else if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
		std::cout << "Error: Server failed to login or register the user, due to unknown reason. " << std::endl;
		exit(1);
	}
	return false;
}



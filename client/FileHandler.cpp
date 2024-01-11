// Name: Sahar Hazan
// ID: 316495092

#include "FileHandler.h"

// This function opens a file, creating directories if necessary. It returns true if the file opens successfully.
bool FileHandler::initializeFile(const std::string& fileDestination, std::fstream& thisFile, bool writeFlag)
{
	std::filesystem::path pathToCheck = fileDestination;
	try {
		std::filesystem::create_directories(pathToCheck.parent_path());
		auto flag = writeFlag ?  (std::fstream::out | std::fstream::app) : std::fstream::in;
		thisFile.open(fileDestination.c_str(), flag);
		return thisFile.is_open();
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
	return false;
}

// Opens a file in binary mode. It ensures directory creation and returns true if the file is successfully opened.
bool FileHandler::openBinaryFile(const std::string& fileDestination, std::fstream& thisFile, bool writeFlag)
{
	std::filesystem::path pathToCheck = fileDestination;
	try {
		std::filesystem::create_directories(pathToCheck.parent_path());
		auto flags = writeFlag ? (std::fstream::binary | std::fstream::out) : (std::fstream::binary | std::fstream::in);
		thisFile.open(fileDestination.c_str(), flags);
		return thisFile.is_open();
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
}

// Opens a binary file for writing, overwriting any existing content. Creates directories if they don't exist.
bool FileHandler::openAndOverwriteFile(const std::string& fileDestination, std::fstream& thisFile)
{
	std::filesystem::path pathToCheck = fileDestination;
	try {
		std::filesystem::create_directories(pathToCheck.parent_path());
		auto flag = std::fstream::binary | std::fstream::out | std::fstream::trunc;
		thisFile.open(fileDestination.c_str(), flag);
		return thisFile.is_open();
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
	return false;
}

// Closes the file and returns true on successful closure. 
bool FileHandler::finalizeFile(std::fstream& thisFile)
{
	try {
		thisFile.close();
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
}

// Writes content into a file. fstream object is received, so the calling function is responsible for opening. 
bool FileHandler::writeToFile(std::fstream& thisFile, const char* content, uint32_t size)
{
	try {
		thisFile.write(content, size);
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
}

// Reads a specified amount of data from a file into a buffer.
bool FileHandler::loadFromFile(std::fstream& thisFile, char* payload, uint32_t count)
{
	try {
		thisFile.read(payload, count);
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
	return false;
}

// Given a buffer, writes the buffer in hex into a file. (Inspired by the code provided by the lecturers, with small tweaks)
void FileHandler::hexifyToFile(std::fstream& thisFile, const char* buffer, unsigned int length)
{
	std::ios::fmtflags f(thisFile.flags());
	thisFile << std::hex;
	for (size_t i = 0; i < length; i++)
		thisFile << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]);
	thisFile.flags(f);
}

// Checks if a file exists at the given path.
bool FileHandler::fileExists(const std::string& fileDestination)
{
	std::filesystem::path pathToCheck = fileDestination;
	return std::filesystem::exists(fileDestination);
}

// Retrieves and returns the size of the specified file.
uint32_t FileHandler::retrieveFileSize(const std::string& fileDestination)
{
	std::filesystem::path pathToCheck = fileDestination;
	return std::filesystem::file_size(pathToCheck);
}
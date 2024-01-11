// Name: Sahar Hazan
// ID: 316495092


#pragma once
#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>


class FileHandler {
public:
	bool initializeFile(const std::string&, std::fstream&, bool);
	bool openBinaryFile(const std::string&, std::fstream&, bool);
	bool openAndOverwriteFile(const std::string&, std::fstream&);
	bool finalizeFile(std::fstream&);
	bool writeToFile(std::fstream&, const char*, uint32_t);
	bool loadFromFile(std::fstream&, char*, uint32_t);
	void hexifyToFile(std::fstream&, const char*, unsigned int);

	bool fileExists(const std::string&);
	uint32_t retrieveFileSize(const std::string&);
};


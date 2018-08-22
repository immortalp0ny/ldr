#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream>


bool readall(std::string& path, char ** pFileData, unsigned int* cbFileData, std::string& errorMessage);

std::string getLastErrorString();
#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <Windows.h>

#define LGC_GREEN 2
#define LGC_LIGHT_GREEN 10

#define LGC_BLUE 1
#define LGC_LIGHT_BLUE 9

#define LGC_CYAN 3
#define LGC_LIGHT_CYAN 11

#define LGC_RED 4
#define LGC_LIGHT_RED 12

#define LGC_YELLOW 6
#define LGC_LIGHT_YELLOW 14

#define LGC_RESET 15

class Logger
{
protected:
	HANDLE hLog;
	bool isCustomLog = false;
	std::string loggerName;
public:
	Logger();
	Logger(HANDLE hLog);
	~Logger();

	void setLoggerName(std::string& loggerName);

	void log(std::string& message, char code, unsigned int color);

	void logMessage(std::string& message);
	void logErrorMessage(std::string& message);
	void logWarningMessage(std::string& message);
	void logInfoMessage(std::string& message);
	void logImportantMessage(std::string& message);
};


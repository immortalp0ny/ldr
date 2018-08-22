#include "stdafx.h"
#include "Logger.h"


Logger::Logger()
{
	hLog = GetStdHandle(STD_OUTPUT_HANDLE);
}

Logger::Logger(HANDLE logHandle)
{
	HANDLE hDefaultLog = GetStdHandle(STD_OUTPUT_HANDLE);
	this->hLog = hLog ? hLog : hDefaultLog;
	
	isCustomLog = this->hLog != hDefaultLog;
}


Logger::~Logger()
{
}

void Logger::setLoggerName(std::string & loggerName)
{
	this->loggerName.insert(0, loggerName);
}

void Logger::log(std::string & message, char code, unsigned int color)
{
	if (!isCustomLog)
		SetConsoleTextAttribute(hLog, color);

	auto t = std::time(nullptr);
	auto tm = *std::localtime(&t);

	std::ostringstream oss;
	oss << std::put_time(&tm, "%d-%m-%Y %H-%M-%S");
	std::string timstampStr = oss.str();

	
	std::stringstream ss;
	ss << "[" << code << "]-[" << timstampStr << "]";
	
	if (!loggerName.empty())
		ss << "-[" << loggerName << "]";
	
	ss << " " << message << std::endl;

	std::string logLine = ss.str();

	DWORD cbWrited = 0;

	if (!isCustomLog)
	{
		FlushConsoleInputBuffer(hLog);
		SetConsoleTextAttribute(hLog, color);
	}

	WriteFile(hLog, logLine.c_str(), logLine.length(), &cbWrited, NULL);

	if (!isCustomLog)
	{
		SetConsoleTextAttribute(hLog, LGC_RESET);
	}
}

void Logger::logMessage(std::string & message)
{
	log(message, '+', LGC_GREEN);
}

void Logger::logErrorMessage(std::string & message)
{
	log(message, '~', LGC_RED);
}

void Logger::logWarningMessage(std::string & message)
{
	log(message, '!', LGC_YELLOW);
}

void Logger::logInfoMessage(std::string & message)
{
	log(message, '?', LGC_BLUE);
}

void Logger::logImportantMessage(std::string & message)
{
	log(message, '$', LGC_CYAN);
}

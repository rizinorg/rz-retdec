/**
 * @file include/r2plugin/console/data_analysis.h
 * @brief implementation of data analysis console (pdza_).
 * @copyright (c) 2020 avast software, licensed under the mit license.
 */

#pragma once

#include "r2plugin/console/console.h"

namespace retdec {
namespace r2plugin {

/**
 * Provides and implements Data Analysis console interface
 * that is shown as pdza_ command in r2.
 */
class DataAnalysisConsole: public Console {
protected:
	/// Protected constructor. DataAnalysisConsole is meant to be used as singleton.
	DataAnalysisConsole();

public:
	/// Calls handle method of singleton.
	static bool handleCommand(const std::string& commad, const R2Database& info);

	/// Representation of pdza command.
	static Console::Command AnalyzeRange;

	/// Representation of pdzaa command.
	static Console::Command AnalyzeWholeBinary;

	static const Console *getInstance() { return &console; }

private:
	/// Implementation of pdza command.
	static RzCmdStatus analyzeRange(RzCore *core, int argc, const char **argv);

	/// Implementation of pdzaa command.
	static RzCmdStatus analyzeWholeBinary(RzCore *core, int argc, const char **argv);

private:
	/// Helper method. Parses arguments of pdza commnad.
	static common::AddressRange parseRange(const std::string& range);

private:
	/// Singleton.
	static DataAnalysisConsole console;
};

};
};

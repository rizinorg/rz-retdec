// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief implementation of data analysis console (pdza_)
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
	/// Singleton.
	static DataAnalysisConsole console;
};

};
};

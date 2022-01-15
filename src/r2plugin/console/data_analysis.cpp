// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Implementation of data analysis console (pdza_)
 */

#include <iostream>
#include <regex>

#include <retdec/utils/io/log.h>

#include "r2plugin/r2retdec.h"
#include "r2plugin/console/data_analysis.h"

using namespace retdec::utils::io;

namespace retdec {
namespace r2plugin {

#define with(T, ...) ([]{ T ${}; __VA_ARGS__; return $; }())

static const RzCmdDescArg args_none[] = {{}};

static const RzCmdDescArg args_range[] = {
	with(RzCmdDescArg,
		$.name = "start";
		$.optional = true;
		$.type = RZ_CMD_ARG_TYPE_NUM;
	),
	with(RzCmdDescArg,
		$.name = "end";
		$.optional = true;
		$.type = RZ_CMD_ARG_TYPE_NUM;
	),
	{},
};

Console::Command DataAnalysisConsole::AnalyzeRange(
	with(RzCmdDescHelp,
		$.summary =
			"Analyze and import functions at specified range. "
			"Default range is range of currently seeked function.";
		$.args = args_range
	),
	analyzeRange
);

Console::Command DataAnalysisConsole::AnalyzeWholeBinary(
	with(RzCmdDescHelp,
		$.summary = "Analyze and import all functions.";
		$.args = args_none
	),
	analyzeWholeBinary
);

DataAnalysisConsole::DataAnalysisConsole(): Console(
	with(RzCmdDescHelp,
		$.summary = "Run RetDec analysis.";
		$.args = args_none
	),
	AnalyzeRange,
	{
		{"a", AnalyzeWholeBinary}
	})
{
}

// this must be down here to be initialized after its commands.
DataAnalysisConsole DataAnalysisConsole::console;

common::AddressRange defaultAnalysisRange(const common::Address& start)
{
	// Magic constant 2000 should be more cleverly set.
	return {start, start+2000};
}

/**
 * Runs decompilation on range of currently seeked function. Optional argument is
 */
RzCmdStatus DataAnalysisConsole::analyzeRange(RzCore *core, int argc, const char **argv)
{
	std::lock_guard<std::recursive_mutex> lock(mutex);
	try {
		R2Database info(*core);
		std::string cache = "";

		common::AddressRange toAnalyze;
		if (argc > 1) {
			ut64 start = rz_num_math(core->num, argv[1]);
			if (argc > 2) {
				ut64 end = rz_num_math(core->num, argv[2]);
				toAnalyze = common::AddressRange(start, end);
			} else {
				toAnalyze = defaultAnalysisRange(start);
			}
		} else {
			auto fnc = info.fetchSeekedFunction();
			toAnalyze = fnc;
			if (fnc.getSize() == 0)
				toAnalyze = defaultAnalysisRange(fnc.getStart());

			cache = cacheName(fnc);
		}

		auto config = createConfig(info, cache);

		// TODO:
		// RetDec experiences off by one error.
		// This should be noted in RetDec issue.
		if (toAnalyze.getStart() != 0)
			toAnalyze.setStart(toAnalyze.getStart()-1);

		config.parameters.selectedRanges.insert(toAnalyze);
		config.parameters.setIsSelectedDecodeOnly(true);

		auto [code, _] = decompile(config, false);
		if (code == nullptr)
			return RZ_CMD_STATUS_ERROR;

		info.setFunctions(config);

		return RZ_CMD_STATUS_OK;
	} catch (const std::exception& e){
		Log::error() << Log::Error << e.what() << std::endl;
		return RZ_CMD_STATUS_ERROR;
	}
}

RzCmdStatus DataAnalysisConsole::analyzeWholeBinary(RzCore *core, int argc, const char **argv)
{
	std::lock_guard<std::recursive_mutex> lock(mutex);
	try {
		R2Database info(*core);
		auto config = createConfig(info, "whole");

		auto [code, _] = decompile(config, false);
		if (code == nullptr)
			return RZ_CMD_STATUS_ERROR;

		// r_core_annotated_code_print(code, nullptr);
		info.setFunctions(config);

		return RZ_CMD_STATUS_OK;
	} catch (const std::exception& e) {
		Log::error() << Log::Error << e.what() << std::endl;
		return RZ_CMD_STATUS_ERROR;
	}
}

}
}

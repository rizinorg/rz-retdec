/**
 * @file src/r2plugin/console/data_analysis.cpp
 * @brief Implementation of data analysis console (pdza_).
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#include <iostream>
#include <regex>

#include <retdec/utils/io/log.h>

#include "r2plugin/r2retdec.h"
#include "r2plugin/console/data_analysis.h"

using namespace retdec::utils::io;

namespace retdec {
namespace r2plugin {

static const RzCmdDescArg args_none[] = {{}};

#define with(T, ...) ([]{ T ${}; __VA_ARGS__; return $; }())

Console::Command DataAnalysisConsole::AnalyzeRange(
	with(RzCmdDescHelp,
		$.summary =
			"Analyze and import functions at specified range. "
			"Default range is range of currently seeked function.";
		$.args = args_none // TODO: "[start-end]"
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

common::AddressRange DataAnalysisConsole::parseRange(const std::string& range)
{
	std::smatch match;
	std::regex rangeRegex("(0x)?([0-9a-fA-F][0-9a-fA-F]*)(?:-|  *)(0x)?([0-9a-fA-F][0-9a-fA-F]*)");

	if (!std::regex_match(range, match, rangeRegex))
		throw DecompilationError("Invalid range: "+range);

	char* end = nullptr;
	size_t base = match[1].str() == "0x" ? 16 : 10;
	auto beginRange = std::strtol(match[2].str().c_str(), &end, base);
	if (end == nullptr || *end != '\0')
		throw DecompilationError("Invalid number: "+match[2].str());

	base = match[3].str() == "0x" ? 16 : 10;
	auto endRange = std::strtol(match[4].str().c_str(), &end, base);
	if (end == nullptr || *end != '\0')
		throw DecompilationError("Invalid number: "+match[4].str());

	return common::AddressRange(beginRange, endRange);
}

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
	R2Database info(*core);
	std::string cache = "";

	common::AddressRange toAnalyze;
// TODO: re-enable
#if 0
	std::string params;
	auto space = std::find(command.begin(), command.end(), ' ');
	if (space != command.end()) {
		params = std::string(std::next(space), command.end());
		toAnalyze = parseRange(params);
	}
	else {
		try {
			auto fnc = binInfo.fetchSeekedFunction();
			toAnalyze = fnc;
			if (fnc.getSize() == 0)
				toAnalyze = defaultAnalysisRange(fnc.getStart());

			cache = cacheName(fnc);
		} catch (DecompilationError){
			toAnalyze = defaultAnalysisRange(binInfo.seekedAddress());
		}
	}
#endif

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

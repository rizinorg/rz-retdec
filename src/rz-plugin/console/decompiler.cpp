// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief implementation of decompiler console (pdz_).
 */

#include <retdec/utils/io/log.h>

#include "rz-plugin/console/decompiler.h"
#include "rz-plugin/console/data_analysis.h"

#define CMD_PREFIX "pdz" /**< Plugin activation command in r2 console.**/

using namespace retdec::utils::io;

namespace retdec {
namespace rzplugin {

#define with(T, ...) ([]{ T ${}; __VA_ARGS__; return $; }())

static const RzCmdDescArg args_none[] = {{}};

DecompilerConsole::DecompilerConsole(): Console(
	with(RzCmdDescHelp,
		$.summary = "Native RetDec decompiler plugin.";
		$.args = args_none
	),
	DecompileCurrent,
	{
		{"*", DecompileCommentCurrent},
		{"a", DecompilerDataAnalysis},
		{"e", ShowUsedEnvironment},
		{"j", DecompileJsonCurrent},
		{"o", DecompileWithOffsetsCurrent}
	})
{
}

const Console::Command DecompilerConsole::DecompileCurrent = {
	with(RzCmdDescHelp,
		$.summary = "Show decompilation result of current function.";
		$.args = args_none
	),
	DecompilerConsole::decompileCurrent
};

const Console::Command DecompilerConsole::DecompileWithOffsetsCurrent = {
	with(RzCmdDescHelp,
		$.summary = "Show current decompiled function side by side with offsets.";
		$.args = args_none
	),
	DecompilerConsole::decompileWithOffsetsCurrent
};

const Console::Command DecompilerConsole::DecompileJsonCurrent = {
	with(RzCmdDescHelp,
		$.summary = "Dump current decompiled function as JSON.";
		$.args = args_none
	),
	DecompilerConsole::decompileJsonCurrent
};

const Console::Command DecompilerConsole::DecompileCommentCurrent = {
	with(RzCmdDescHelp,
		$.summary = "Return decompilation of current function to r2 as comment.";
		$.args = args_none
	),
	DecompilerConsole::decompileCommentCurrent
};

const Console::CommandGroup DecompilerConsole::DecompilerDataAnalysis(DataAnalysisConsole::getInstance());

const Console::Command DecompilerConsole::ShowUsedEnvironment = {
	with(RzCmdDescHelp,
		$.summary = "Show environment variables.";
		$.args = args_none
	),
	DecompilerConsole::showEnvironment
};

// this must be down here to be initialized after its commands.
DecompilerConsole DecompilerConsole::console;

config::Config DecompilerConsole::createConsoleConfig(const RizinDatabase& binInfo)
{
	auto fnc = binInfo.fetchSeekedFunction();
	auto config = createConfig(binInfo, cacheName(fnc));
	config.parameters.selectedRanges.insert(fnc);
	config.parameters.setIsSelectedDecodeOnly(true);

	binInfo.fetchFunctionsAndGlobals(config);

	return config;
}

bool DecompilerConsole::registerCommands(RzCmd* cmd)
{
	RzCmdDesc* root_desc = rz_cmd_get_root(cmd);
	return DecompilerConsole::console.registerConsole(cmd, root_desc, CMD_PREFIX);
}

RzAnnotatedCode *DecompilerConsole::runDecompile(RzCore *core)
{
	std::lock_guard<std::recursive_mutex> lock(mutex);
	try {
		RizinDatabase info(*core);
		auto config = createConsoleConfig(info);
		auto [code, _] = decompile(config, true);
		return code;
	} catch (const std::exception& e) {
		Log::error() << Log::Error << e.what() << std::endl;
		return nullptr;
	}
}

RzCmdStatus DecompilerConsole::decompileCurrent(RzCore *core, int argc, const char **argv)
{
	auto code = runDecompile(core);
	if (code == nullptr)
		return RZ_CMD_STATUS_ERROR;

	rz_core_annotated_code_print(code, nullptr);
	return RZ_CMD_STATUS_OK;
}

RzCmdStatus DecompilerConsole::decompileWithOffsetsCurrent(RzCore *core, int argc, const char **argv)
{
	auto code = runDecompile(core);
	if (code == nullptr)
		return RZ_CMD_STATUS_ERROR;

	RzVector *offsets = rz_annotated_code_line_offsets(code);
	rz_core_annotated_code_print(code, offsets);
	rz_vector_free(offsets);

	return RZ_CMD_STATUS_OK;
}


RzCmdStatus DecompilerConsole::decompileJsonCurrent(RzCore *core, int argc, const char **argv)
{
	auto code = runDecompile(core);
	if (code == nullptr)
		return RZ_CMD_STATUS_ERROR;

	rz_core_annotated_code_print_json(code);
	return RZ_CMD_STATUS_OK;
}

RzCmdStatus DecompilerConsole::decompileCommentCurrent(RzCore *core, int argc, const char **argv)
{
	auto code = runDecompile(core);
	if (code == nullptr)
		return RZ_CMD_STATUS_ERROR;

	rz_core_annotated_code_print_comment_cmds(code);
	return RZ_CMD_STATUS_OK;
}

RzCmdStatus DecompilerConsole::showEnvironment(RzCore *core, int argc, const char **argv)
{
	std::lock_guard<std::recursive_mutex> lock(mutex);
	Log::info() << Log::Color::Green << "Environment:" << std::endl;

	std::string padding = "    ";

	std::string outDir;
	try {
		outDir = getOutDirPath("").string();
	} catch(const DecompilationError &e) {
		outDir = e.what();
	}

	Log::info() << padding << "DEC_SAVE_DIR = " << outDir << std::endl;
	return RZ_CMD_STATUS_OK;
}

}
}

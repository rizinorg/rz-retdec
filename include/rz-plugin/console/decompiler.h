// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief implementation of decompiler console (pdz_)
 */

#pragma once

#include "rz-plugin/console/console.h"
#include "rz-plugin/rzretdec.h"

namespace retdec {
namespace rzplugin {

/**
 * Decompiler class. Provides and implements interface for decompiler
 * console that user sees after typing pdz_ command.
 */
class DecompilerConsole: public Console {
protected:
	DecompilerConsole();

public:
	/// Register all decompilation commands into the given RzCmd instance.
	static bool registerCommands(RzCmd* cmd);

	/// Deregister all decompilation commands into the given RzCmd instance.
	static bool deregisterCommands(RzCmd* cmd);

public:
	/// Representation of pdz command.
	static const Console::Command DecompileCurrent;

	/// Representation of pdzo command.
	static const Console::Command DecompileWithOffsetsCurrent;

	/// Representation of pdzj command.
	static const Console::Command DecompileJsonCurrent;

	/// Representation of pdz* command.
	static const Console::Command DecompileCommentCurrent;

	/// Representation of pdza command.
	static const Console::CommandGroup DecompilerDataAnalysis;

	/// Representation of pdze command.
	static const Console::Command ShowUsedEnvironment;

private:
	/// Run decompilation for a command.
	static RzAnnotatedCode *runDecompile(RzCore *core);

	/// Implementation of pdz command.
	static RzCmdStatus decompileCurrent(RzCore *core, int argc, const char **argv);

	/// Implementation of pdzj command.
	static RzCmdStatus decompileJsonCurrent(RzCore *core, int argc, const char **argv);

	/// Implementation of pdzo command.
	static RzCmdStatus decompileWithOffsetsCurrent(RzCore *core, int argc, const char **argv);

	/// Implementation of pdz* command.
	static RzCmdStatus decompileCommentCurrent(RzCore *core, int argc, const char **argv);

	/// Implementation of pdze command.
	static RzCmdStatus showEnvironment(RzCore *core, int argc, const char **argv);

	static config::Config createConsoleConfig(const RizinDatabase& binInfo);

private:
	/// Singleton.
	static DecompilerConsole console;
};

};
};

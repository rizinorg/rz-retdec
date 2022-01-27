// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Rizin include interface
 */

#pragma once

#include <map>
#include <tuple>

#include "rz-plugin/data.h"

namespace retdec {
namespace rzplugin {

/**
 * @brief Provides console user interface.
 *
 * Provides interface (and implementation) for
 * handling console arguments. This class does
 * not implement logic only interface for
 * registering handler methods on required actions.
 */
class Console {
public:
	/// Abstract Command or Command Group Description that can be registered into RzCmd.
	class CommandDesc {
	public:
		virtual bool registerDesc(RzCmd* cmd, RzCmdDesc* parent, const std::string& prefix) const =0;
	};

	/// Concrete Command that has no subcommands.
	class Command : public CommandDesc {
	public:
		const RzCmdDescHelp help;
		const RzCmdArgvCb cb;

		Command(const RzCmdDescHelp help, const RzCmdArgvCb cb)
			: help(help), cb(cb) {}
		bool registerDesc(RzCmd* cmd, RzCmdDesc* parent, const std::string& prefix) const override;
	};

	/// Concrete Command Group that contains the Commands of its contained console.
	struct CommandGroup : public CommandDesc {
		const Console * const subconsole;
	public:
		CommandGroup(const Console * const subconsole)
			: subconsole(subconsole) {}
		bool registerDesc(RzCmd* cmd, RzCmdDesc* parent, const std::string& prefix) const override;
	};

	using NamedCommandDesc = std::pair<const std::string, const CommandDesc&>;

protected:
	Console(const RzCmdDescHelp& help, const Command& root_cmd, const std::vector<NamedCommandDesc>&);

public:
	bool registerConsole(RzCmd* cmd, RzCmdDesc* parent, const std::string& prefix) const;

private:
	const RzCmdDescHelp _help;
	const Command _root_cmd;
	std::map<const std::string, const CommandDesc&> _callbacks;
};

}
}

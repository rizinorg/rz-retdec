// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Rizin console interface
 */

#include <iostream>
#include <regex>

#include "rz-plugin/console/console.h"

namespace retdec {
namespace rzplugin {

bool Console::Command::registerDesc(RzCmd* cmd, RzCmdDesc* parent, const std::string& prefix) const
{
	return !!rz_cmd_desc_argv_new(cmd, parent, prefix.c_str(), cb, &help);
}

bool Console::CommandGroup::registerDesc(RzCmd* cmd, RzCmdDesc* parent, const std::string& prefix) const
{
	return subconsole->registerConsole(cmd, parent, prefix);
}

Console::Console(
	const RzCmdDescHelp& help,
	const Command& root_cmd,
	const std::vector<Console::NamedCommandDesc>& cmds):
		_help(help),
		_root_cmd(root_cmd),
		_callbacks(cmds.begin(), cmds.end())
{
}

bool Console::registerConsole(RzCmd* cmd, RzCmdDesc* parent, const std::string& prefix) const
{
	RzCmdDesc *root_cd = rz_cmd_desc_group_new(cmd, parent, prefix.c_str(), _root_cmd.cb, &_root_cmd.help, &_help);
	if (!root_cd) {
		return false;
	}
	for (const auto& subcmd : _callbacks) {
		if (!subcmd.second.registerDesc(cmd, root_cd, prefix + subcmd.first)) {
			return false;
		}
	}
	return true;
}

}
}

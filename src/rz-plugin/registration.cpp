// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @brief Module that implements registration logic to r2 console
 */

#include <mutex>

#include <retdec/utils/io/log.h>
#include <rz_core.h>

#include "rz-plugin/data.h"
#include "rz-plugin/console/decompiler.h"

using namespace retdec::rzplugin;
using namespace retdec::utils::io;

static bool rz_retdec_init(RzCore *core)
{
	return DecompilerConsole::registerCommands(core->rcmd);
}

// Structure containing plugin info.
RzCorePlugin rz_core_plugin_retdec = {
	/* .name = */ "rz-retdec",
	/* .desc = */ "RetDec integration",
	/* .license = */ "LGPL3",
	/* .author = */ "RizinOrg and Avast",
	/* .version = */ nullptr,
	/* .init = */ rz_retdec_init,
	/* .fini = */ nullptr
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif

// This will register the r2plugin in r2 console.
RZ_API RzLibStruct rizin_plugin = {
	/* .type = */ RZ_LIB_TYPE_CORE,
	/* .data = */ &rz_core_plugin_retdec,
	/* .version = */ RZ_VERSION,
	/* .free = */ nullptr,
	/* .pkgname */ "rz-retdec"
};

#endif

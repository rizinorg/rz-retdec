// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @brief Module that implements registration logic to r2 console
 */

#include <mutex>

#include <retdec/utils/io/log.h>
#include <rz_core.h>

#include "r2plugin/r2data.h"
#include "r2plugin/console/decompiler.h"

using namespace retdec::r2plugin;
using namespace retdec::utils::io;

static bool rz_retdec_init(RzCore *core)
{
	return DecompilerConsole::registerCommands(core->rcmd);
}

// Structure containing plugin info.
RzCorePlugin rz_core_plugin_retdec = {
	/* .name = */ "r2retdec",
	/* .desc = */ "RetDec integration",
	/* .license = */ "MIT",
	/* .author = */ "Avast",
	/* .version = */ "0.2",
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
	/* .pkgname */ "retdec-r2plugin"
};

#endif

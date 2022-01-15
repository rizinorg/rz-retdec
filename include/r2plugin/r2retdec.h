// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Main module of the retdec-r2plugin.
 */

#ifndef R2PLUGIN_R2RETDEC_H
#define R2PLUGIN_R2RETDEC_H

#include <rz_util/rz_annotated_code.h>
#include <rz_core.h>

#include "r2plugin/r2data.h"
#include "filesystem_wrapper.h"

namespace retdec {
namespace r2plugin {

/// Global Mutex for all RetDec state.
extern std::recursive_mutex mutex;

RZ_API RzAnnotatedCode* decompile(RzCore *core, ut64 addr);

std::pair<RzAnnotatedCode*, retdec::config::Config> decompile(
		const R2Database &binInfo,
		const common::AddressRange& decompileRange,
		bool useCache = true,
		bool fetchR2Data = true);

std::pair<RzAnnotatedCode*, retdec::config::Config> decompile(
		config::Config& config,
		bool useCache);

config::Config createConfig(const R2Database& binInfo, const std::string& cacheSuffix = "");

std::string cacheName(const common::Function& fnc);

fs::path getOutDirPath(const fs::path &suffix = "");

}
}


#endif //R2PLUGIN_R2RETDEC_H

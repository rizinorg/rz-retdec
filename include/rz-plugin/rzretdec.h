// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Main module of rz-retdec
 */

#ifndef RZ_RETDEC_RZRETDEC_H
#define RZ_RETDEC_RZRETDEC_H

#include <rz_util/rz_annotated_code.h>
#include <rz_core.h>

#include "rz-plugin/data.h"
#include "filesystem_wrapper.h"

namespace retdec {
namespace rzplugin {

/// Global Mutex for all RetDec state.
extern std::recursive_mutex mutex;

RZ_API RzAnnotatedCode* decompile(RzCore *core, ut64 addr);

std::pair<RzAnnotatedCode*, retdec::config::Config> decompile(
		const RizinDatabase &binInfo,
		const common::AddressRange& decompileRange,
		bool useCache = true,
		bool fetchR2Data = true);

std::pair<RzAnnotatedCode*, retdec::config::Config> decompile(
		config::Config& config,
		bool useCache);

config::Config createConfig(const RizinDatabase& binInfo, const std::string& cacheSuffix = "");

std::string cacheName(const common::Function& fnc);

fs::path getOutDirPath(const fs::path &suffix = "");

}
}


#endif

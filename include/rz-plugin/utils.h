// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Specific output format utilities.
 */

#ifndef RETDEC_R2PLUGIN_R2UTILS_H
#define RETDEC_R2PLUGIN_R2UTILS_H

#include <map>
#include <string>
#include <vector>

#include <rz_core.h>

namespace retdec {
namespace rzplugin {

class FormatUtils {
private:
	~FormatUtils();

public:
	static const std::string convertTypeToLlvm(const RzTypeDB *tdb, const RzType *type);
	static const std::string convertTypeToLlvm(const std::string &ctype);
	static const std::string convertLlvmTypeToC(const std::string &ctype);

	static const std::string joinTokens(
			const std::vector<std::string> &tokens,
			const std::string &delim = " ");
	static std::vector<std::string> splitTokens(
			const std::string &type,
			char delim = ' ');

	static std::string stripName(const std::string &name);

protected:
	static const std::string getTypeDefinition(const std::string &token);

private:
	static const std::map<const std::string, const std::string> _primitives;
	static const std::vector<std::string> _typeKeywords;
};

}
}

#endif /*RETDEC_R2PLUGIN_R2UTILS_H*/

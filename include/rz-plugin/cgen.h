// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief C code generation and token marking
 */

#ifndef RETDEC_R2PLUGIN_R2CGEN_H
#define RETDEC_R2PLUGIN_R2CGEN_H

#include <map>
#include <optional>
#include <rapidjson/document.h>

#include <rz_util/rz_annotated_code.h>

namespace retdec {
namespace rzplugin {

class R2CGenerator {
public:
	RzAnnotatedCode* generateOutput(const std::string &rdoutJson) const;

protected:
	RzAnnotatedCode* provideAnnotations(const rapidjson::Document &root) const;
	std::optional<RSyntaxHighlightType> highlightTypeForToken(const std::string &token) const;

private:
	static std::map<const std::string, RSyntaxHighlightType> _hig2token;
};

}
}

#endif /*RETDEC_R2PLUGIN_R2CGEN_H*/

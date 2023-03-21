// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief C code generation and token marking.
 */

#include <fstream>
#include <optional>

#include "rz-plugin/data.h"
#include "rz-plugin/cgen.h"

using namespace retdec::rzplugin;

/**
 * Translation map between decompilation JSON output and r2 understandable
 * annotations.
 */
std::map<const std::string, RSyntaxHighlightType> R2CGenerator::_hig2token = {
	// {"nl", ... }
	// {"ws", ... }
	// {"punc", ... }
	// {"op", ... }
	{"i_var", RZ_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE},
	// {"i_var", RZ_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE},
	// {"i_mem", RZ_SYNTAX_HIGHLIGHT_TYPE_DATATYPE},
	{"i_lab", RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD},
	{"i_fnc", RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME},
	{"i_arg", RZ_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER},
	{"keyw" , RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD},
	{"type" , RZ_SYNTAX_HIGHLIGHT_TYPE_DATATYPE},
	{"preproc" , RZ_SYNTAX_HIGHLIGHT_TYPE_KEYWORD},
	{"inc", RZ_SYNTAX_HIGHLIGHT_TYPE_COMMENT},
	{"l_bool", RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_int", RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_fp", RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_str", RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_sym", RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"l_ptr", RZ_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE},
	{"cmnt" , RZ_SYNTAX_HIGHLIGHT_TYPE_COMMENT}
};

/**
 * Translaction map interaction method. Usage of this method is preffered to obtain r2 understandable
 * annotation from JSON config token.
 */
std::optional<RSyntaxHighlightType> R2CGenerator::highlightTypeForToken(const std::string &token) const
{
	if (_hig2token.count(token)) {
		return _hig2token.at(token);
	}

	return {};
}

/**
 * Generates annotated code from RetDec's output obrained as JSON.
 *
 * @param root The root of JSON decompilation output.
 */
RzAnnotatedCode* R2CGenerator::provideAnnotations(const rapidjson::Document &root) const
{
	RzAnnotatedCode *code = rz_annotated_code_new(nullptr);
	if (code == nullptr) {
		throw DecompilationError("unable to allocate memory");
	}

	std::ostringstream planecode;
	std::optional<unsigned long> lastAddr;

	if (!root["tokens"].IsArray()) {
		throw DecompilationError("malformed JSON");
	}

	auto tokens = root["tokens"].GetArray();
	for (auto& token: tokens) {
		if (token.HasMember("addr")) {
			std::string addrRaw = token["addr"].GetString();
			if (addrRaw == "") {
				lastAddr.reset();
			}
			else {
				try {
					lastAddr = std::stoll(addrRaw, nullptr, 16);
				} catch (std::exception &e) {
					throw DecompilationError("invalid address: "+addrRaw);
				}
			}
			continue;
		}
		else if (token.HasMember("val") && token.HasMember("kind")) {
			unsigned long bpos = planecode.tellp();
			planecode << token["val"].GetString();
			unsigned long epos = planecode.tellp();

			if (lastAddr.has_value()) {
				RzCodeAnnotation annotation = {};
				annotation.type = RZ_CODE_ANNOTATION_TYPE_OFFSET;
				annotation.offset.offset = lastAddr.value();
				annotation.start = bpos;
				annotation.end = epos;
				rz_annotated_code_add_annotation(code, &annotation);
			}

			auto higlight = highlightTypeForToken(token["kind"].GetString());
			if (higlight.has_value()) {
				RzCodeAnnotation annotation = {};
				annotation.type = RZ_CODE_ANNOTATION_TYPE_SYNTAX_HIGHLIGHT;
				annotation.syntax_highlight.type = higlight.value();
				annotation.start = bpos;
				annotation.end = epos;
				rz_annotated_code_add_annotation(code, &annotation);
			}
		}
		else {
			throw DecompilationError("malformed RetDec JSON output");
		}
	}

	std::string str = planecode.str();
	code->code = reinterpret_cast<char *>(rz_mem_alloc(str.length() + 1));
	if(!code->code) {
		rz_annotated_code_free(code);
		throw DecompilationError("unable to allocate memory");
	}
	memcpy(code->code, str.c_str(), str.length());
	code->code[str.length()] = '\0';

	return code;
}

/**
 * Generates output by parsing RetDec's JSON output and calling R2CGenerator::provideAnnotations.
 */
RzAnnotatedCode* R2CGenerator::generateOutput(const std::string &rdoutJson) const
{
	std::ifstream jsonFile(rdoutJson, std::ios::in | std::ios::binary);
	if (!jsonFile) {
		throw DecompilationError("unable to open RetDec output: "+rdoutJson);
	}

	std::string jsonContent;
	jsonFile.seekg(0, std::ios::end);
	jsonContent.resize(jsonFile.tellg());
	jsonFile.seekg(0, std::ios::beg);
	jsonFile.read(&jsonContent[0], jsonContent.size());
	jsonFile.close();

	rapidjson::Document root;
	rapidjson::ParseResult success = root.Parse(jsonContent);
	if (!success) {
		throw DecompilationError("unable to parse RetDec JSON output");
	}

	return provideAnnotations(root);
}

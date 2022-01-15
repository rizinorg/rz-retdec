// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Information gathering from Rizin and user
 */

#ifndef RETDEC_R2PLUGIN_R2_INFO_H
#define RETDEC_R2PLUGIN_R2_INFO_H

#include <exception>
#include <map>
#include <string>

#include <rz_core.h>
#include <rz_analysis.h>

#include <retdec/config/config.h>

namespace retdec {
namespace r2plugin {

using R2Address = ut64;

/**
 * R2Database implements wrapper around R2 API functions.
 */
class R2Database {
public:
	R2Database(RzCore &core);

public:
	std::string fetchFilePath() const;

	void setFunction(const common::Function &fnc) const;
	void copyFunctionData(const common::Function &fnc, RzAnalysisFunction& r2fnc) const;

	void setFunctions(const config::Config &rdconfig) const;

	common::Function fetchFunction(ut64 addr) const;
	common::Function fetchSeekedFunction() const;

	void fetchFunctionsAndGlobals(config::Config &rdconfig) const;

	void fetchFunctionLocalsAndArgs(common::Function &function, RzAnalysisFunction &r2fnc) const;
	void fetchFunctionCallingconvention(common::Function &function, RzAnalysisFunction &r2fnc) const;
	void fetchFunctionReturnType(common::Function &function, RzAnalysisFunction &r2fnc) const;
	size_t fetchWordSize() const;
	R2Address seekedAddress() const;
	const RzCore& core() const;

protected:
	void fetchGlobals(config::Config &rdconfig) const;
	common::Function convertFunctionObject(RzAnalysisFunction &fnc) const;
	void fetchExtraArgsData(common::ObjectSequentialContainer &args, RzAnalysisFunction &r2fnc) const;

private:
	RzCore &_r2core;
	static std::map<const std::string, const common::CallingConventionID> _r2rdcc;
};

class DecompilationError: public std::exception {
public:
	DecompilationError(const std::string &msg) : _message(msg) {}
	~DecompilationError() throw() {}
	const char* what() const throw() { return _message.c_str(); }

private:
	std::string _message;
};

}
}

#endif /*RETDEC_R2PLUGIN_R2_INFO_H*/

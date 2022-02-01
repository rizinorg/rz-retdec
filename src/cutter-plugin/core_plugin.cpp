// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Main module of the retdec-cutter-plugin.
 */

#include <exception>

#include "cutter-plugin/core_plugin.h"
#include "rz-plugin/rzretdec.h"

void RetDecPlugin::setupPlugin()
{
}

void RetDecPlugin::setupInterface(MainWindow *)
{
}

void RetDecPlugin::registerDecompilers()
{
	Core()->registerDecompiler(new RetDec(Core()));
}

RetDecPlugin::RetDec::RetDec(QObject *parent)
	: Decompiler("r2retdec", "RetDec", parent)
{
}

void RetDecPlugin::RetDec::decompileAt(RVA addr)
{
	RzAnnotatedCode* code = nullptr;

	try {
		code = retdec::rzplugin::decompile(Core()->core(), addr);
	}
	catch (const std::exception& e) {
		code = rz_annotated_code_new(strdup((
				std::string("decompilation error: ")+e.what()).c_str()));
	}
	catch (...) {
		code = nullptr;
	}

	if (code == nullptr)
		code = rz_annotated_code_new(strdup("decompilation error: unable to decompile function at this offset"));

	emit finished(code);
}

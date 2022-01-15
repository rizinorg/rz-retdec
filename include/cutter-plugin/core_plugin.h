// SPDX-FileCopyrightText: 2020 Avast Software
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file
 * @brief Main module of the retdec-cutter-plugin.
 */

#ifndef RETDEC_R2PLUGIN_CORE_PLUGIN_H
#define RETDEC_R2PLUGIN_CORE_PLUGIN_H

#include <QObject>
#include <QtPlugin>
#include <plugins/CutterPlugin.h>

#include "Decompiler.h"

class RetDecPlugin : public QObject, CutterPlugin {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "re.rizin.cutter.plugins.retdec")
    Q_INTERFACES(CutterPlugin)

    class RetDec: public Decompiler {
    public:
	RetDec(QObject *parent = nullptr);
	void decompileAt(RVA addr) override;
    };

public:
    void setupPlugin() override;
    void setupInterface(MainWindow *main) override;
    void registerDecompilers() override;

    QString getName() const override {
	    return "RetDec Decompiler (rz-retdec)";
    }

    QString getAuthor() const override {
	    return "RizinOrg and Avast";
    }

    QString getDescription() const override {
	    return "RetDec plugin for Cutter";
    }

    QString getVersion() const override {
	    return "0.2";
    }
};


#endif // RETDEC_R2PLUGIN_CORE_PLUGIN_H

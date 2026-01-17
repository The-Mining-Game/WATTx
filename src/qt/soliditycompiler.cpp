// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/soliditycompiler.h>

#include <QProcess>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QFile>
#include <QDir>

SolidityCompiler::SolidityCompiler(QObject *parent)
    : QObject(parent)
{
}

SolidityCompiler::~SolidityCompiler()
{
}

bool SolidityCompiler::isSolcAvailable()
{
    QString output, errorOutput;
    int exitCode = executeSolc({"--version"}, QString(), output, errorOutput);
    return exitCode == 0 && output.contains("solc");
}

QString SolidityCompiler::getSolcVersion()
{
    QString output, errorOutput;
    int exitCode = executeSolc({"--version"}, QString(), output, errorOutput);

    if (exitCode != 0) {
        return QString();
    }

    // Parse version from output like "solc, the solidity compiler commandline interface\nVersion: 0.8.19+commit.7dd6d404.Linux.g++"
    QRegularExpression re("Version:\\s*([^\\s]+)");
    QRegularExpressionMatch match = re.match(output);

    if (match.hasMatch()) {
        return match.captured(1);
    }

    return QString();
}

int SolidityCompiler::executeSolc(const QStringList& args, const QString& input,
                                  QString& output, QString& errorOutput)
{
    QProcess process;

    // Find solc in PATH
    QString solcPath = QStandardPaths::findExecutable("solc");
    if (solcPath.isEmpty()) {
        // Try common locations including user's local bin
        QString homeDir = QDir::homePath();
        QStringList searchPaths = {
            "/usr/bin/solc",
            "/usr/local/bin/solc",
            "/snap/bin/solc",
            homeDir + "/.local/bin/solc"
        };
        for (const QString& path : searchPaths) {
            if (QFile::exists(path)) {
                solcPath = path;
                break;
            }
        }
    }

    if (solcPath.isEmpty()) {
        errorOutput = "Solidity compiler (solc) not found. Please install solc and ensure it's in your PATH.";
        return -1;
    }

    process.start(solcPath, args);

    if (!input.isEmpty()) {
        process.write(input.toUtf8());
        process.closeWriteChannel();
    }

    if (!process.waitForFinished(30000)) { // 30 second timeout
        errorOutput = "Compilation timed out";
        return -1;
    }

    output = QString::fromUtf8(process.readAllStandardOutput());
    errorOutput = QString::fromUtf8(process.readAllStandardError());

    return process.exitCode();
}

SolidityCompiler::CompileResult SolidityCompiler::compile(const QString& sourceCode,
                                                          const QString& contractName)
{
    CompileResult result;
    result.success = false;

    if (sourceCode.trimmed().isEmpty()) {
        result.errorMessage = "Source code is empty";
        return result;
    }

    // Check if solc is available
    if (!isSolcAvailable()) {
        result.errorMessage = "Solidity compiler (solc) not found. Please install solc:\n"
                             "  Ubuntu/Debian: sudo apt install solc\n"
                             "  Or: sudo snap install solc";
        return result;
    }

    QString output, errorOutput;

    // Compile with combined JSON output
    // Using stdin (-) for source code input
    QStringList args = {
        "--combined-json", "bin,abi",
        "--optimize",
        "-"  // Read from stdin
    };

    int exitCode = executeSolc(args, sourceCode, output, errorOutput);

    // Parse warnings from stderr (even on success)
    if (!errorOutput.isEmpty()) {
        QStringList lines = errorOutput.split('\n', Qt::SkipEmptyParts);
        for (const QString& line : lines) {
            if (line.contains("Warning:")) {
                result.warnings.append(line.trimmed());
            }
        }
    }

    if (exitCode != 0) {
        // Compilation failed
        result.errorMessage = errorOutput.isEmpty() ? "Compilation failed" : errorOutput;
        return result;
    }

    // Parse JSON output
    if (!parseOutput(output, result, contractName)) {
        if (result.errorMessage.isEmpty()) {
            result.errorMessage = "Failed to parse compiler output";
        }
        return result;
    }

    result.success = true;
    return result;
}

bool SolidityCompiler::parseOutput(const QString& jsonOutput, CompileResult& result,
                                   const QString& contractName)
{
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonOutput.toUtf8(), &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        result.errorMessage = "JSON parse error: " + parseError.errorString();
        return false;
    }

    if (!doc.isObject()) {
        result.errorMessage = "Invalid compiler output format";
        return false;
    }

    QJsonObject root = doc.object();

    if (!root.contains("contracts")) {
        result.errorMessage = "No contracts found in output";
        return false;
    }

    QJsonObject contracts = root["contracts"].toObject();

    if (contracts.isEmpty()) {
        result.errorMessage = "No contracts compiled";
        return false;
    }

    // Extract all contract names
    // Keys are in format "<stdin>:ContractName" or "filename.sol:ContractName"
    for (auto it = contracts.begin(); it != contracts.end(); ++it) {
        QString fullName = it.key();
        QString name = fullName;
        int colonPos = fullName.lastIndexOf(':');
        if (colonPos >= 0) {
            name = fullName.mid(colonPos + 1);
        }
        result.contractNames.append(name);
    }

    // Select contract to use
    QString selectedKey;

    if (!contractName.isEmpty()) {
        // Look for specific contract
        for (auto it = contracts.begin(); it != contracts.end(); ++it) {
            if (it.key().endsWith(":" + contractName) || it.key() == contractName) {
                selectedKey = it.key();
                break;
            }
        }
        if (selectedKey.isEmpty()) {
            result.errorMessage = "Contract '" + contractName + "' not found in source";
            return false;
        }
    } else {
        // Use first contract (or last if multiple - typically the main contract)
        selectedKey = contracts.keys().last();
    }

    result.selectedContract = selectedKey;
    int colonPos = selectedKey.lastIndexOf(':');
    if (colonPos >= 0) {
        result.selectedContract = selectedKey.mid(colonPos + 1);
    }

    QJsonObject contractObj = contracts[selectedKey].toObject();

    // Extract bytecode
    if (contractObj.contains("bin")) {
        result.bytecode = contractObj["bin"].toString();
    } else {
        result.errorMessage = "No bytecode in compilation output";
        return false;
    }

    // Extract ABI
    if (contractObj.contains("abi")) {
        QJsonValue abiValue = contractObj["abi"];
        if (abiValue.isString()) {
            result.abi = abiValue.toString();
        } else if (abiValue.isArray()) {
            QJsonDocument abiDoc(abiValue.toArray());
            result.abi = QString::fromUtf8(abiDoc.toJson(QJsonDocument::Compact));
        }
    }

    return true;
}

QMap<QString, SolidityCompiler::ContractData> SolidityCompiler::getContracts(const QString& sourceCode)
{
    QMap<QString, ContractData> contracts;

    QString output, errorOutput;
    QStringList args = {
        "--combined-json", "bin,abi",
        "--optimize",
        "-"
    };

    int exitCode = executeSolc(args, sourceCode, output, errorOutput);
    if (exitCode != 0) {
        return contracts;
    }

    QJsonDocument doc = QJsonDocument::fromJson(output.toUtf8());
    if (!doc.isObject()) {
        return contracts;
    }

    QJsonObject root = doc.object();
    if (!root.contains("contracts")) {
        return contracts;
    }

    QJsonObject contractsObj = root["contracts"].toObject();

    for (auto it = contractsObj.begin(); it != contractsObj.end(); ++it) {
        QString fullName = it.key();
        QString name = fullName;
        int colonPos = fullName.lastIndexOf(':');
        if (colonPos >= 0) {
            name = fullName.mid(colonPos + 1);
        }

        QJsonObject contractObj = it.value().toObject();
        ContractData data;
        data.bytecode = contractObj["bin"].toString();

        QJsonValue abiValue = contractObj["abi"];
        if (abiValue.isString()) {
            data.abi = abiValue.toString();
        } else if (abiValue.isArray()) {
            QJsonDocument abiDoc(abiValue.toArray());
            data.abi = QString::fromUtf8(abiDoc.toJson(QJsonDocument::Compact));
        }

        contracts[name] = data;
    }

    return contracts;
}

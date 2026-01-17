// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOLIDITYCOMPILER_H
#define SOLIDITYCOMPILER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>

/**
 * @brief Wrapper class for external Solidity compiler (solc)
 *
 * This class provides functionality to compile Solidity smart contracts
 * using the external solc compiler. Users must have solc installed and
 * available in their PATH.
 */
class SolidityCompiler : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Result structure for compilation output
     */
    struct CompileResult {
        bool success;                       ///< Whether compilation succeeded
        QString bytecode;                   ///< Compiled bytecode (hex string)
        QString abi;                        ///< Contract ABI (JSON string)
        QString errorMessage;               ///< Error message if compilation failed
        QStringList warnings;               ///< Compilation warnings
        QStringList contractNames;          ///< List of contract names in source
        QString selectedContract;           ///< Currently selected contract name
    };

    /**
     * @brief Contract data for multi-contract files
     */
    struct ContractData {
        QString bytecode;
        QString abi;
    };

    explicit SolidityCompiler(QObject *parent = nullptr);
    ~SolidityCompiler();

    /**
     * @brief Compile Solidity source code
     * @param sourceCode The Solidity source code to compile
     * @param contractName Optional specific contract to extract (for multi-contract files)
     * @return CompileResult with bytecode, ABI, or error information
     */
    static CompileResult compile(const QString& sourceCode, const QString& contractName = "");

    /**
     * @brief Check if solc compiler is available in PATH
     * @return true if solc is found and executable
     */
    static bool isSolcAvailable();

    /**
     * @brief Get the version string of the installed solc compiler
     * @return Version string (e.g., "0.8.19+commit.7dd6d404") or empty if not available
     */
    static QString getSolcVersion();

    /**
     * @brief Get all contracts from a compilation result
     * @param sourceCode The Solidity source code
     * @return Map of contract names to their bytecode/ABI data
     */
    static QMap<QString, ContractData> getContracts(const QString& sourceCode);

private:
    /**
     * @brief Execute solc and return output
     * @param args Command line arguments for solc
     * @param input Optional stdin input
     * @param output Output from solc (stdout)
     * @param errorOutput Error output from solc (stderr)
     * @return Exit code from solc
     */
    static int executeSolc(const QStringList& args, const QString& input,
                          QString& output, QString& errorOutput);

    /**
     * @brief Parse solc JSON output
     * @param jsonOutput The JSON output from solc --combined-json
     * @param result The CompileResult to populate
     * @param contractName Optional specific contract to extract
     * @return true if parsing succeeded
     */
    static bool parseOutput(const QString& jsonOutput, CompileResult& result,
                           const QString& contractName = "");
};

#endif // SOLIDITYCOMPILER_H

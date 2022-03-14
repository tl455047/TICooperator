///
/// Copyright (C) 2022, tl455047
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef S2E_PLUGINS_TICooperator_H
#define S2E_PLUGINS_TICooperator_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/ExecutionTracers/TestCaseGenerator.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>


namespace s2e {
namespace plugins {


enum S2E_TICooperator_COMMANDS {
    // TODO: customize list of commands here
    TICOOP_PRINT_STATISTICS,
};

struct S2E_TICooperator_COMMAND {
    S2E_TICooperator_COMMANDS Command;
    union {
        // Command parameters go here
        uint64_t param;
    };
};



class TICooperator : public Plugin, public IPluginInvoker {
    S2E_PLUGIN
public:
    TICooperator(S2E *s2e);
    void initialize();
    
private:
    testcases::TestCaseGenerator *m_TestCaseGenerator;
    klee::ExecutionState *m_currentState;

    static double m_timeout;
    static unsigned int constraintsCount;
    static unsigned int solvedConstraints;
    static unsigned int unsolvedConstraints;
    
    std::string dirPath;
    std::ofstream *statOfs;
    std::vector<size_t> retAddr;

    typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

    // Allow the guest to communicate with this plugin using s2e_invoke_plugin
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
    
    void onEngineShutdown();
    void onTimer();
    void onStateForkDecide(S2EExecutionState *state, 
                           const klee::ref<klee::Expr> &condition_, 
                           bool &allowForking);
    void onSymbolicAddress(S2EExecutionState *state,
                           klee::ref<klee::Expr> symbolicAddress,
                           uint64_t concreteAddress,
                           bool &concretize,
                           CorePlugin::symbolicAddressReason reason);
    void generateTestcase(S2EExecutionState *state, 
                          klee::ref<klee::Expr> &condition, 
                          bool conditionIsTrue, 
                          ArrayVec &symbObjects, 
                          std::vector<std::vector<unsigned char>> &concreteObjects);
    void initTestcaseDirectory();
    void readSelectedRetAddr();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_TICooperator_H
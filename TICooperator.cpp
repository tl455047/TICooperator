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

#include "TICooperator.h"

#include <algorithm>
#include <cstdlib>
#include <klee/Internal/System/Time.h>
#include <klee/Solver.h>
#include <llvm/Support/FileSystem.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/ExecutionTracers/TestCaseGenerator.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

namespace s2e {
namespace plugins {

namespace {
//
// This class can optionally be used to store per-state plugin data.
//
// Use it as follows:
// void TICooperator::onEvent(S2EExecutionState *state, ...) {
//     DECLARE_PLUGINSTATE(TICooperatorState, state);
//     plgState->...
// }
//

class TICooperatorState: public PluginState {
    // Declare any methods and fields you need here
private:

public:
    TICooperatorState() {
        
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new TICooperatorState();
    }

    virtual ~TICooperatorState() {
        // Destroy any object if needed
    }

    virtual TICooperatorState *clone() const {
        return new TICooperatorState(*this);
    }
};
}

S2E_DEFINE_PLUGIN(TICooperator, "Describe what the plugin does here", "", );

TICooperator::TICooperator(S2E *s2e) 
                  : Plugin(s2e), 
                    m_TestCaseGenerator(nullptr),
                    m_currentState(nullptr),
                    dirPath(""),
                    statOfs(nullptr) { }

unsigned int TICooperator::constraintsCount = 0;
unsigned int TICooperator::solvedConstraints = 0;
unsigned int TICooperator::unsolvedConstraints = 0;
double TICooperator::m_timeout = 0;

void TICooperator::initialize() {

    initTestcaseDirectory();
    readSelectedRetAddr();

    std::string statsFilename = s2e()->getOutputDirectory() + "/Solving.stats";
    statOfs = new std::ofstream(statsFilename, std::ios::out);
    
    // use TestCaseGenerator
    m_TestCaseGenerator = s2e()->getPlugin<testcases::TestCaseGenerator>();

    // for simple set fixed timeout 
    m_timeout = 3600000;
    // for symbolic address
    //s2e()->getCorePlugin()->onSymbolicAddress.connect(sigc::mem_fun(*this, &TICooperator::onSymbolicAddress));

    /**
     * For evaluating each branch condition calculated time in concolic path.
     * In order to restrict execution path in concolic path, we disable state forking.
     * However, we still want to solve branched state condition, to compare the solving 
     * time and solving result between full symbolic and critical bytes only symbolic.
     * klee::Executor::executeInstruction will handle symbolic execution for each instruction,
     * when instruction is branch instruction, conditional S2EExecutor::fork will be invoked,
     * then S2EExecutor::fork will call S2EExecutor::doFork, when it is condition fork, and 
     * the condition in not constant, core event onStateForkDecide will be invoked.
     * State fork will be disabled if onStateForkDecide returning false or current state's
     * forkDisabled is true, then klee::Executor::fork will be invoked, if condition is
     * constant or state fork is disabled, fork will be skipped. klee::Executor trys to 
     * invert condition, and solve, an create new state, finally it returns StatePair.
     * After S2EExecutor::fork is returned, notifyFork will be invoked, and this will 
     * trigger core event onStateFork.
     * 
     */

    /**
     * This plugin is designated for exploring paths based on the result of taint inference.
     * This plugin will cover following functions:
     * 1. Disable state forking, but still collect the branched state constraints, and solve it.
     *    We reuse most of code in klee::Executor::fork, only without adding the branched state 
     * to addedstate in S2Eexecutor.
     * 2. Record the Constraints solving information.
     * 3. Generate testcase for each branched state constraints, this can be done by invoking 
     *    generateTestCase from another plugin TestCaseGenerator.
     * 4. Solving branched condtion only when the pc is at the instruction we want.
     * 
     * taint inference can collects critical bytes for each cmp instruction in current execution 
     * path, therefore these critical bytes are only effective in current path. However, in 
     * symbolic execution, we state forking for each symbolic constraints in branch, each state
     * represents an unique execution path, critical bytes for current state is not effective in 
     * new state, we need to redo taint inference to obtaint new critical bytes for new state.
     * To cooperate with taint inference properly, we choose to disable state fork in branch
     * condition, although still collect constraints and solve it.
     * 
     * Why we do not just generate testcase by ourselves? 
     * Since critical byte may be part of input, s2e state only maintains concrete bytes for 
     * symbolic data, other original part of concrete data is not, user need to handle it manually.
     * Fortunately, TestCaseGenerator has already covered this functions, when making symbolic for
     * files, s2ecmd sends the rest of concrete data to plugin TestCaseGenerator. Then, 
     * TestCaseGenerator is able to reassemble the testcase.
     * 
     */

    // let's try to collect new branch condition and solve it in core event onStateForkDecide.
    s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &TICooperator::onStateForkDecide));
    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &TICooperator::onEngineShutdown));
    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &TICooperator::onTimer));    
}   

void TICooperator::onEngineShutdown() {
    std::string failedStatsFilename = s2e()->getOutputDirectory() + "/failed.stats";
    std::ofstream failedOfs(failedStatsFilename, std::ios::out);
    unsigned int solvedBranch = 0, failedBranch = 0;
    
    if (failedOfs) {
        for(auto it = retAddr.begin(); it != retAddr.end(); it++) {
        
            if (isStepped.find(it->first) == isStepped.end()) {    
                failedOfs << std::hex << it->first << " " << std::dec << it->second << "\n";
                failedBranch++;
            }
            else 
                solvedBranch++;
        }
    }

    failedOfs.close();

    onTimer();

    *statOfs << klee::util::getUserTime() << "," 
             << solvedBranch << "," << failedBranch << "," << retAddr.size() << "\n";
    statOfs->close();
    delete statOfs;
}

void TICooperator::onTimer() {
    std::stringstream ss;
    ss << solvedConstraints << "," << unsolvedConstraints << ","
       << constraintsCount << "\n";
    // update solvedConstraints / unsolvedConstraints / constraintsCount
    s2e()->getDebugStream() << "TICooperator: solved / unsolved / total: "  << ss.str();
    // write solvedConstraints / unsolvedConstraints / constraintsCount to file
    // user time ???
    *statOfs << klee::util::getUserTime() << "," << ss.str();
    statOfs->flush();

    // terminate state when time limit is achived
    if (klee::util::getUserTime() >= m_timeout)
        s2e()->getExecutor()->terminateState(*m_currentState, "timeout");
}

void TICooperator::onStateForkDecide(S2EExecutionState *state, 
                                           const klee::ref<klee::Expr> &condition_, 
                                           bool &allowForking) {
    // always disable forking  
    if (allowForking) {
        allowForking = false;
    }
     
    if (m_currentState == nullptr)
        m_currentState = static_cast<klee::ExecutionState *>(state);

    assert(!state->isRunningConcrete());
    auto condition = state->simplifyExpr(condition_);

    // If we are passed a constant, no need to do anything
    if (auto ce = dyn_cast<ConstantExpr>(condition)) {
        return;
    }
    
    // we have disabled state fork, therefore we need to collect
    // new state fork branch condition and solve them manually.
    // check if the cmp is we want
    uint64_t currentPc = state->regs()->getPc(); 
    auto it = std::find_if(retAddr.begin(), retAddr.end(), 
        [&currentPc](const std::pair<uint64_t, unsigned int> &e) -> bool
        {   
            if (currentPc < e.first)
              return false;

            return ((currentPc - e.first) < 0x10);
        }); 
    
    uint64_t ret_addr;
    unsigned int cmpId;
         
    if (it == retAddr.end()) {

        ret_addr = currentPc;
        cmpId = 0;
    }
    else {
        ret_addr = it->first;
        cmpId = it->second;
    }

    if (it == retAddr.end()) {
      
      return;

    }
    else if (isStepped.find(it->first) == isStepped.end()) {
        
        isStepped.emplace(it->first);
    
    }

    // Evaluate the expression using the current variable assignment
    klee::ref<klee::Expr> evalResult = state->concolics->evaluate(condition);
    ConstantExpr *ce = dyn_cast<ConstantExpr>(evalResult);
    check(ce, "Could not evaluate the expression to a constant.");
    bool conditionIsTrue = ce->isTrue();

    // Build constraints for branched state
    ConstraintManager tmpConstraints = state->constraints();
    if (conditionIsTrue) {
        tmpConstraints.addConstraint(Expr::createIsZero(condition));
    }
    else {
        tmpConstraints.addConstraint(condition);
    }
    
    // Extract symbolic objects
    ArrayVec symbObjects = state->symbolics;
    std::vector<std::vector<unsigned char>> concreteObjects;
    struct klee::Query q(tmpConstraints, ConstantExpr::alloc(0, Expr::Bool));
    auto solver = state->solver();
    
    constraintsCount++;
    if (!solver->getInitialValues(q, symbObjects, concreteObjects)) {
        // failed to solve new branch condition
        unsolvedConstraints++;
    }
    else {
        // success
        solvedConstraints++;

        // generate concrete input for branched condition
        generateTestcase(state, condition, conditionIsTrue,
                         symbObjects, concreteObjects, ret_addr, cmpId);
    }

    /*if (isStepped.size() == retAddr.size())
        s2e()->getExecutor()->terminateState(*m_currentState, "all requested inst. stepped");*/

}

void TICooperator::generateTestcase(S2EExecutionState *state,
                                          klee::ref<klee::Expr> &condition,
                                          bool conditionIsTrue,
                                          ArrayVec &symbObjects,
                                          std::vector<std::vector<unsigned char>> &concreteObjects, 
                                          uint64_t ret_addr, unsigned int cmpId) {
    // create branched state and use it to solve concrete input,
    // we won't add the branched state to addedState.    
    ExecutionState *branchedState;
    branchedState = state->clone();

    // Update concrete values for the branched state
    branchedState->concolics->clear();
    for (unsigned i = 0; i < symbObjects.size(); ++i) {
        branchedState->concolics->add(symbObjects[i], concreteObjects[i]);
    }

    // Add constraint to branched state
    if (conditionIsTrue) {
        if (!branchedState->addConstraint(Expr::createIsZero(condition))) {
            abort();
        }
    }
    else {
        if (!branchedState->addConstraint(condition)) {
            abort();
        }
    }
    
    S2EExecutionState *newState = static_cast<S2EExecutionState *>(branchedState);
    char idStr[32];
    std::snprintf(idStr, 32, "/id:%06u-%lx-%u", newState->getID() - 1, ret_addr, cmpId);

    // generate concrete input through branched state condition
    m_TestCaseGenerator->generateTestCases(newState, std::string(idStr), testcases::TestCaseType::TC_FILE);
    
    // release branched state
    delete branchedState;
}

void TICooperator::initTestcaseDirectory() {
    dirPath = s2e()->getOutputDirectory() + "/testcase-";
    std::error_code mkdirError = llvm::sys::fs::create_directories(dirPath);
    if (mkdirError) {
        s2e()->getDebugStream() << "Could not create testcase directory " << dirPath << " error: " << mkdirError.message()
                  << "\n";
        exit(-1);
    }
    mode_t m = umask(0);
    umask(m);
    chmod(dirPath.c_str(), 0775 & ~m);
}

void TICooperator::readSelectedRetAddr() {
    std::ifstream ifs("ret_addr");
    size_t instRetAddr;
    unsigned int cmpId;
    if (!ifs) {
        s2e()->getDebugStream() << "Unable to open ret_addr\n";
    }
    while(!ifs.eof()) {
        ifs >> std::hex >> instRetAddr >> std::dec >> cmpId;
        retAddr.emplace(std::make_pair(instRetAddr, cmpId));
    }
    ifs.close();
}

void TICooperator::onSymbolicAddress(S2EExecutionState *state,
                                           klee::ref<klee::Expr> symbolicAddress,
                                           uint64_t concreteAddress,
                                           bool &concretize,
                                           CorePlugin::symbolicAddressReason reason) {
    if (reason == CorePlugin::symbolicAddressReason::MEMORY) {

        s2e()->getDebugStream() << "SymbolicAddress: " << hexval(concreteAddress) << "\n";
        // off??-by-??one byte   
        // try to solve concreteAddress + 1
        uint64_t value = concreteAddress + 1;
        auto constraint = EqExpr::create(symbolicAddress, ConstantExpr::create(value, Expr::Int64));
        
        // add constraint
        if (!state->addConstraint(constraint, true)) {
        
            s2e()->getDebugStream() << "Cannot add constraint\n";
            return;
        
        } 

        s2e()->getDebugStream() << "Constraint solved\n";
        std::vector<std::pair<std::string, std::vector<unsigned char>>> solution;
        const std::pair<std::string, std::vector<unsigned char>> vp = solution[0];

        // solve
        if (!state->getSymbolicSolution(solution)) {
            
            s2e()->getDebugStream() << "Cannot solve constraint\n";
            return;   
        
        }

        std::string input;
        for (const auto __byte : vp.second) {
            input.push_back(__byte);
        }

        // Write the solved input to the file.
        /*std::string filename = "exploit.bin";
        std::statOfstream ofs(filename);
        ofs << input;*/
        
        return;
    
    }
}

void TICooperator::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize)
{
    S2E_TICooperator_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_TICooperator_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        // TODO: add custom commands here
        case TICOOP_PRINT_STATISTICS: {
            onTimer();
            break;
        }
        default:
            getWarningsStream(state) << "Unknown command " << command.Command << "\n";
            break;
    }
}

} // namespace plugins
} // namespace s2e

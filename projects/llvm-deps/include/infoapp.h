#ifndef INFOAPP_H_
#define INFOAPP_H_

#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/Module.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "Infoflow.h"

#include <set>

using namespace llvm;
using namespace deps;

namespace  {

class InfoAppPass : public ModulePass {  
  public:
  InfoAppPass() : ModulePass(ID) {}
  static char ID;
  bool runOnModule(Module &M);
  
  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequired<Infoflow>();
    AU.setPreservesAll();
  }

  private:
    Infoflow* infoflow;
    DenseMap<const Value*, bool> xformMap;
    std::set<StringRef> whiteSet;
    std::set<StringRef> blackSet;

    virtual void doInitialization();
    virtual void doFinalization();
  
    /// Traverse instructions from the module(M) and identify tainted
    /// instructions.
    /// if it returns true: tag it to replace it with dummy
    ///       returns false: do not change
  
    bool trackSoln(Module &M,
                   InfoflowSolution* soln,
                   CallInst* sinkCI,
                   std::string& kinds);

    bool checkBackwardTainted(Value &V, InfoflowSolution* soln, bool direct=true);
    bool checkForwardTainted(Value &V, InfoflowSolution* soln, bool direct=true);
    bool isConstAssign(const std::set<const Value *> vMap);
    void removeChecksForFunction(Function& F);
    void format_ioc_report_func(const Value* val, raw_string_ostream& rs);
    uint64_t getIntFromVal(Value* val);
    uint64_t getColFromVal(Value* val);
  void getStringFromVal(Value* val, std::string& output);
};  //class
  
typedef  struct {
  const char* func;
  const char* fname;
  bool conversion;
  bool overflow;
  bool shift;
} rmChecks;

/* ID for InfoAppPass */
char InfoAppPass::ID = 0;

static void registerInfoAppPass(const PassManagerBuilder &, PassManagerBase &PM)
{
    PM.add(new InfoAppPass());
}

static RegisterStandardPasses
RegisterInfoAppPass(PassManagerBuilder::EP_OptimizerLast, registerInfoAppPass);

  
//static RegisterPass<InfoAppPass>
//XX ("infoapp", "implements infoapp", true, true);
  
}  // nameapce

#endif

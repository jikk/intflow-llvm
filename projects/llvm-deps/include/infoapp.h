#ifndef INFOAPP_H_
#define INFOAPP_H_

#include "llvm/Pass.h"
#include "llvm/Module.h"
#include "llvm/ADT/StringRef.h"

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

static RegisterPass<InfoAppPass>
XX ("infoapp", "implements infoapp", true, true);
  
}  // nameapce

//namespace llvm {
//  
//INITIALIZE_PASS_BEGIN(InfoAppPass, "infoapp", "Promote Memory to Register",
//                      false, false)
////INITIALIZE_PASS_DEPENDENCY(PromotePass)
//INITIALIZE_PASS_END(InfoAppPass, "infoapp", "Promote Memory to Register",
//                    false, false)
//  
//}
#endif

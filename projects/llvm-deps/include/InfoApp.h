#ifndef INFOAPP_H_
#define INFOAPP_H_

#include "llvm/Pass.h"
#include "llvm/Module.h"
#include "llvm/ADT/StringRef.h"

#include "Infoflow.h"

#include <set>

namespace deps {

using namespace llvm;

class InfoApp : public ModulePass {  
  public:
  InfoApp() : ModulePass(ID) {
  	initializeInfoAppPass(*PassRegistry::getPassRegistry());
  }
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

  
};  //class

/* ID for InfoApp */
char InfoApp::ID = 99;

static RegisterPass<InfoApp>
XX ("InfoApp", "InfoApp", false, true);

}  // nameapce

#endif

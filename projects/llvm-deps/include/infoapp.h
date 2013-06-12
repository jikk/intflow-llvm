#ifndef INFOAPP_H_
#define INFOAPP_H_

#include "llvm/Pass.h"
#include <llvm/Module.h>

namespace deps {

using namespace llvm;

class InfoAppPass : public ModulePass {
  static char ID;
  InfoAppPass() : ModulePass(ID) {}

  public:
  bool runOnModule(Module &M) {
    doInitialization();
    doFinalization();
    return false;
  }

  private:
    virtual void doInitialization();
    virtual void doFinalization();
};  // class

/* ID for InfoAppPass */
char InfoAppPass::ID = 99;

}  // nameapce

#endif

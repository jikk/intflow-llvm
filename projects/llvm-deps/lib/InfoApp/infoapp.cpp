#include "llvm/Module.h"
#include "llvm/Support/Debug.h"

#include "Infoflow.h"
#include "Slice.h"

#include "Infoapp.h"

namespace deps {

using namespace llvm;

void
InfoAppPass::doInitialization() {
  infoflow = &getAnalysis<Infoflow>();
  DEBUG(errs() << "[InfoApp] doInitialization\n");
}

void
InfoAppPass::doFinalization() {
  DEBUG(errs() << "[InfoApp] doFinalization\n");
}

bool
InfoAppPass::runOnModule(Module &M) {
    doInitialization();
    doFinalization();
    return false;
  }

}  //namespace deps

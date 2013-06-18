#include <sstream>

#include "llvm/Instructions.h"
#include "llvm/Function.h"
#include "llvm/Module.h"
#include "llvm/Support/Debug.h"

#include "Infoflow.h"
#include "Slice.h"

#include "Infoapp.h"

//#define __REACH__

using std::set;

namespace deps {

using namespace llvm;

void
InfoAppPass::doInitialization() {
  infoflow = &getAnalysis<Infoflow>();
  DEBUG(errs() << "[InfoApp] doInitialization\n");
  
  //XXX: whiteSet
  
  //XXX: blackSet
  
}

void
InfoAppPass::doFinalization() {
  DEBUG(errs() << "[InfoApp] doFinalization\n");
}

bool
InfoAppPass::runOnModule(Module &M) {
  //assigning unique IDs to each overflow locations.
  static uint64_t unique_id = 0;

  doInitialization();

  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        if (CallInst* ci = dyn_cast<CallInst>(ii)) {
          
          /*
           List of overflow report functions

           LVal: 4th arg, RVal: 5th arg
           __ioc_report_add_overflow()
           __ioc_report_sub_overflow()
           __ioc_report_mul_overflow()
           
           Val: 7th arg
           __ioc_report_conversion()
           */
          
          /*
           XXX: this more about the following functions
           __ioc_report_div_error()
           __ioc_report_rem_error()
           __ioc_report_shl_bitwidth()
           __ioc_report_shr_bitwidth()
           __ioc_report_shl_strict()
           */
          
          Function* func = ci->getCalledFunction();
          if (!func)
            continue;
          
          /* XXX: fix it and extend it */
          if (func->getName() == "__ioc_report_add_overflow" ||
              func->getName() == "__ioc_report_sub_overflow" ||
              func->getName() == "__ioc_report_mul_overflow")
          {
            //check for arg. count
            assert(ci->getNumOperands() == 8);
            
            std::stringstream SS;
            std::set<std::string> kinds;
            
            SS << unique_id++;
            std::string sinkKind = "overflow" + SS.str();
            
            Value* lval = ci->getOperand(4);
            Value* rval = ci->getOperand(5);
            
            infoflow->setUntainted(sinkKind, *lval);
            infoflow->setDirectPtrUntainted(sinkKind, *lval);
#ifdef __REACH__
            infoflow->setReachPtrUntainted(sinkKind, *lval);
#endif
            
            infoflow->setUntainted(sinkKind, *rval);
            infoflow->setDirectPtrUntainted(sinkKind, *rval);
#ifdef __REACH__
            infoflow->setReachPtrUntainted(sinkKind, *rval);
#endif
            
            kinds.insert(sinkKind);
            
            InfoflowSolution* soln = infoflow->greatestSolution(kinds, false);
            xformMap[ci] = TrackSoln(M, soln);
            
          } else if (func->getName() == "__ioc_report_conversion") {
            //check for arg. count
            assert(ci->getNumOperands() == 8);
            
            std::stringstream SS;
            std::set<std::string> kinds;
            
            SS << unique_id++;
            std::string sinkKind = "overflow" + SS.str();
            
            Value* val = ci->getOperand(7);

            infoflow->setUntainted(sinkKind, *val);
            infoflow->setDirectPtrUntainted(sinkKind, *val);
            infoflow->setReachPtrUntainted(sinkKind, *val);
            
            kinds.insert(sinkKind);
            InfoflowSolution* soln = infoflow->greatestSolution(kinds, false);
            xformMap[ci] = TrackSoln(M, soln);
          }
        }
      }
    }
  }

  doFinalization();
  return false;
}
  
bool
InfoAppPass::TrackSoln(Module &M, InfoflowSolution* soln) {
  //need optimization or parallelization
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        //instruction is tainted
        if (checkTainted(*ii, soln)) {
          if (CallInst* ci = dyn_cast<CallInst>(ii)) {
            //check for whitelisting / blacklisting
            Function* func = ci->getCalledFunction();

            if (!func) continue;
            
            std::set<StringRef>::const_iterator wi =
                whiteSet.find(func->getName());
            
            if (whiteSet.end() != wi) {
              return true;
            }
            
            std::set<StringRef>::const_iterator bi =
                blackSet.find(func->getName());
  
            if (blackSet.end() != bi) {
              return false;
            }
          }
        }
      }
    }
  }
  return false;
}

bool
InfoAppPass::checkTainted(Value &V, InfoflowSolution* soln) {
  bool ret = (!soln->isTainted(V));
  ret = ret || (!soln->isDirectPtrTainted(V));

#ifdef __REACH__
  // XXX: not sure about Reachable pointer sets.
  ret = || (!soln->isReachPtrTainted(V));
#endif

  return ret;
}
  

}  //namespace deps

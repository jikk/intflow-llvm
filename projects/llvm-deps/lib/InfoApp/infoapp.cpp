#include <sstream>

#include "llvm/Instructions.h"
#include "llvm/Function.h"
#include "llvm/Module.h"
#include "llvm/Support/Debug.h"

#include "Infoflow.h"
#include "Slice.h"

#include "Infoapp.h"

#define __DIRECT__
//#define __REACH__

using std::set;

namespace deps {

using namespace llvm;

void
InfoAppPass::doInitialization() {
  infoflow = &getAnalysis<Infoflow>();
  DEBUG(errs() << "[InfoApp] doInitialization\n");
  
  //init. whitelist(whiteSet)
  for (unsigned int i=0;
       i < (sizeof(wLst) / sizeof(wLst[0]));
       i++) {
    whiteSet.insert(wLst[i]);
  }
  
  //init. blacklist(blackSet)
  for (unsigned int i=0;
       i < (sizeof(bLst) / sizeof(bLst[0]));
       i++) {
    blackSet.insert(bLst[i]);
  }
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
            
            
            //tagging lVal
#ifdef __DIRECT__
            infoflow->setDirectPtrUntainted(sinkKind, *lval);
#endif
#ifdef __REACH__
            infoflow->setReachPtrUntainted(sinkKind, *lval);
#endif
            
            //tagging rVal
            infoflow->setUntainted(sinkKind, *rval);
#ifdef __DIRECT__
            infoflow->setDirectPtrUntainted(sinkKind, *rval);
#endif
#ifdef __REACH__
            infoflow->setReachPtrUntainted(sinkKind, *rval);
#endif
            kinds.insert(sinkKind);
            InfoflowSolution* soln = infoflow->greatestSolution(kinds, false);
            xformMap[ci] = trackSoln(M, soln, ci, sinkKind);
            
          } else if (func->getName() == "__ioc_report_conversion") {
            //check for arg. count
            assert(ci->getNumOperands() == 8);
            
            std::stringstream SS;
            std::set<std::string> kinds;
            
            SS << unique_id++;
            std::string sinkKind = "overflow" + SS.str();
            
            Value* val = ci->getOperand(7);

            //tagging unary arg
            infoflow->setUntainted(sinkKind, *val);
#ifdef __DIRECT__
            infoflow->setDirectPtrUntainted(sinkKind, *val);
#endif
#ifdef __REACH__
            infoflow->setReachPtrUntainted(sinkKind, *val);
#endif
            kinds.insert(sinkKind);
            InfoflowSolution* soln = infoflow->greatestSolution(kinds, false);
            xformMap[ci] = trackSoln(M, soln, ci, sinkKind);
          }
        }
      }
    }
  }

  doFinalization();
  return false;
}
  
bool
InfoAppPass::trackSoln(Module &M,
                        InfoflowSolution* soln,
                        CallInst* sinkCI,
                        std::string& kind)
  {
  //need optimization or parallelization
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        //instruction is tainted
        if (checkBackwardTainted(*ii, soln)) {
          if (CallInst* ci = dyn_cast<CallInst>(ii)) {
            //check for whitelisting / blacklisting
            Function* func = ci->getCalledFunction();

            if (!func) continue;
            
            std::set<StringRef>::const_iterator wi =
                whiteSet.find(func->getName());
            if (whiteSet.end() != wi) {
              
              //trace back to confirm info-flow
              //explicit-flow and cutAfterSinks
              std::set<std::string> kinds;
              kinds.insert("src-" + kind);
      
              InfoflowSolution* fsoln =
                infoflow->leastSolution(kinds, false, true);
             
              return checkForwardTainted(*sinkCI, fsoln);
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
InfoAppPass::checkBackwardTainted(Value &V, InfoflowSolution* soln) {
  bool ret = (!soln->isTainted(V));
  
#ifdef __DIRECT__
  ret = ret || (!soln->isDirectPtrTainted(V));
#endif
#ifdef __REACH__
  // XXX: not sure about Reachable pointer sets.
  ret = || (!soln->isReachPtrTainted(V));
#endif

  return ret;
}
  
  
bool
InfoAppPass::checkForwardTainted(Value &V, InfoflowSolution* soln) {
  bool ret = (soln->isTainted(V));
    
#ifdef __DIRECT__
  ret = ret || (soln->isDirectPtrTainted(V));
#endif
#ifdef __REACH__
  // XXX: not sure about Reachable pointer sets.
  ret = || (soln->isReachPtrTainted(V));
#endif
    
  return ret;
}
  
}  //namespace deps

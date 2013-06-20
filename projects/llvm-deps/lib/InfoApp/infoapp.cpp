#include <sstream>

#include "llvm/Instruction.h"
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

static const struct CallTaintEntry bLstSourceSummaries[] = {
  // function  tainted values   tainted direct memory tainted root ptrs
  { "fgets",   TAINTS_RETURN_VAL,  TAINTS_ARG_1,      TAINTS_NOTHING },
  { 0,         TAINTS_NOTHING,     TAINTS_NOTHING,    TAINTS_NOTHING }
};

static const struct CallTaintEntry wLstSourceSummaries[] = {
  // function  tainted values   tainted direct memory tainted root ptrs
  { "gettimeofday",   TAINTS_RETURN_VAL,  TAINTS_ARG_1,      TAINTS_NOTHING },
  { 0,                TAINTS_NOTHING,     TAINTS_NOTHING,    TAINTS_NOTHING }
};
  
CallTaintEntry nothing = { 0, TAINTS_NOTHING, TAINTS_NOTHING, TAINTS_NOTHING };
  
//XXX: same function from SourceSinkAnalysis
static const CallTaintEntry *
findEntryForFunction(const CallTaintEntry *Summaries,
                     const std::string &FuncName) {
  unsigned Index;
  
  if (StringRef(FuncName).startswith("__ioc"))
    return &nothing;
  
  for (Index = 0; Summaries[Index].Name; ++Index) {
    if (Summaries[Index].Name == FuncName)
      return &Summaries[Index];
  }
  // Return the default summary.
  return &Summaries[Index];
}
  
void
InfoAppPass::doInitialization() {
  infoflow = &getAnalysis<Infoflow>();
  DEBUG(errs() << "[InfoApp] doInitialization\n");
}

void
InfoAppPass::doFinalization() {
  DEBUG(errs() << "[InfoApp] doFinalization\n");
  DenseMap<const Value*, bool>::const_iterator xi = xformMap.begin();
  DenseMap<const Value*, bool>::const_iterator xe = xformMap.end();
  
  for (;xi!=xe; xi++) {
    //changed ones
    errs() << "[InfoApp]xformMap:" << xi->second << ":";
    xi->first->dump();
  }
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
          
          if (func->getName() == "__ioc_report_add_overflow" ||
              func->getName() == "__ioc_report_sub_overflow" ||
              func->getName() == "__ioc_report_mul_overflow")
          {
            //check for arg. count
            assert(ci->getNumOperands() == 8);
            DEBUG(errs() << "[InfoApp]numOper:" << ci->getNumOperands() << "\n");
            DEBUG(errs() << "[InfoApp]func_name:" << func->getName() << "\n");
  
            std::stringstream SS;
            std::set<std::string> kinds;
            
            SS << unique_id++;
            std::string sinkKind = "overflow" + SS.str();
            
            Value* lval = ci->getOperand(4);
            Value* rval = ci->getOperand(5);

            //tagging lVal
            infoflow->setUntainted(sinkKind, *lval);
            
            //tagging rVal
            infoflow->setUntainted(sinkKind, *rval);

            kinds.insert(sinkKind);
            InfoflowSolution* soln = infoflow->greatestSolution(kinds, false);
            xformMap[ci] = trackSoln(M, soln, ci, sinkKind);
            
          } else if (func->getName() == "__ioc_report_conversion") {
            //check for arg. count
            assert(ci->getNumOperands() == 10);
            
            std::stringstream SS;
            std::set<std::string> kinds;
            
            SS << unique_id++;
            std::string sinkKind = "overflow" + SS.str();
            
            Value* val = ci->getOperand(7);

            //tagging unary arg
            infoflow->setUntainted(sinkKind, *val);

            kinds.insert(sinkKind);
            InfoflowSolution* soln = infoflow->greatestSolution(kinds, false);
            
            //check for simple const. assignment
            //getting valeMap
            std::set<const Value *> vMap;
            soln->getValueMap(vMap);

            if(isConstAssign(vMap))
            {
              //replace it for simple const. assignment
              xformMap[ci] = true;
            } else {
              xformMap[ci] = trackSoln(M, soln, ci, sinkKind);
            }
          }
        }
      }
    }
  }
  doFinalization();
  return false;
}

//XXX: now it is too messy. the function need some clean-up  
bool
InfoAppPass::trackSoln(Module &M,
                        InfoflowSolution* soln,
                        CallInst* sinkCI,
                        std::string& kind)
{
  DEBUG(errs() << "[InfoApp]trackSoln:" << "\n");
  //by default do not change/replace.
  bool ret = false;
    
  //need optimization or parallelization
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        //instruction is tainted
        if (checkBackwardTainted(*ii, soln)) {
          DEBUG(errs() << "[InfoApp]checkBackwardTainted:");
          DEBUG(ii->dump());
          
          if (CallInst* ci = dyn_cast<CallInst>(ii)) {
            Function* func = ci->getCalledFunction();

            if (!func) continue;
            
            //check for white-listing
            const CallTaintEntry *entry =
              findEntryForFunction(wLstSourceSummaries, func->getName());

            if (entry->Name) {
              DEBUG(errs() << "[InfoApp]white-list:" << func->getName() <<"\n");
              std::set<std::string> kinds;
              std::string srcKind = "src0" + kind;
              kinds.insert(srcKind);
              
              //TODO: need per white-list entry setting required
              const CallTaintSummary* vSum = &(entry->ValueSummary);
              const CallTaintSummary* dSum = &(entry->DirectPointerSummary);
              const CallTaintSummary* rSum = &(entry->RootPointerSummary);
              
              //vSum
              if (vSum->TaintsReturnValue) {
                infoflow->setTainted(srcKind, *ci);
              }

              for (unsigned ArgIndex = 0;
                   ArgIndex < vSum->NumArguments;
                   ++ArgIndex) {
                
                if (vSum->TaintsArgument[ArgIndex]) {
                  infoflow->setTainted(srcKind, *(ci->getOperand(ArgIndex)));
                }
              }
              
              //dSum
              if (dSum->TaintsReturnValue) {
                infoflow->setDirectPtrTainted(srcKind, *ci);
              }
              
              for (unsigned ArgIndex = 0;
                   ArgIndex < dSum->NumArguments;
                   ++ArgIndex) {
                
                if (vSum->TaintsArgument[ArgIndex]) {
                  infoflow->setDirectPtrTainted(srcKind, *(ci->getOperand(ArgIndex)));
                }
              }

              //rSum
              if (rSum->TaintsReturnValue) {
                infoflow->setReachPtrTainted(srcKind, *ci);
              }
              
              for (unsigned ArgIndex = 0;
                   ArgIndex < rSum->NumArguments;
                   ++ArgIndex) {
                
                if (rSum->TaintsArgument[ArgIndex]) {
                  infoflow->setReachPtrTainted(srcKind, *(ci->getOperand(ArgIndex)));
                }
              }
            
              //trace-back to confirm infoflow with forward slicing
              //explicit-flow and cutAfterSinks.
              InfoflowSolution* fsoln =
                infoflow->leastSolution(kinds, false, true);              
              
              Function* sinkFunc = sinkCI->getCalledFunction();
              if(sinkFunc->getName() == "__ioc_report_conversion") {
                ret = checkForwardTainted(*(sinkCI->getOperand(7)), fsoln);

              } else if (sinkFunc->getName() == "__ioc_report_add_overflow" ||
                         sinkFunc->getName() == "__ioc_report_sub_overflow" ||
                         sinkFunc->getName() == "__ioc_report_mul_overflow")
              {
                ret = (checkForwardTainted(*(sinkCI->getOperand(4)), fsoln) ||
                       checkForwardTainted(*(sinkCI->getOperand(5)), fsoln));

              } else {
                assert(false && "not __ioc_report function");
              }
            }

            //check for black-listing
            entry =
              findEntryForFunction(bLstSourceSummaries, func->getName());
            
            if (entry->Name) {
              DEBUG(errs() << "[InfoApp]black-list:" << func->getName() <<"\n");
              std::set<std::string> kinds;
              std::string srcKind = "src1" + kind;
              kinds.insert(srcKind);
              
              //TODO: need per white-list entry setting required
              const CallTaintSummary* vSum = &(entry->ValueSummary);
              const CallTaintSummary* dSum = &(entry->DirectPointerSummary);
              const CallTaintSummary* rSum = &(entry->RootPointerSummary);
              
              //vSum
              if (vSum->TaintsReturnValue) {
                infoflow->setTainted(srcKind, *ci);
              }
              
              for (unsigned ArgIndex = 0;
                   ArgIndex < vSum->NumArguments;
                   ++ArgIndex) {
                
                if (vSum->TaintsArgument[ArgIndex]) {
                  infoflow->setTainted(srcKind, *(ci->getOperand(ArgIndex)));
                }
              }
              
              //dSum
              if (dSum->TaintsReturnValue) {
                infoflow->setDirectPtrTainted(srcKind, *ci);
              }
              
              for (unsigned ArgIndex = 0;
                   ArgIndex < dSum->NumArguments;
                   ++ArgIndex) {
                
                if (vSum->TaintsArgument[ArgIndex]) {
                  infoflow->setDirectPtrTainted(srcKind, *(ci->getOperand(ArgIndex)));
                }
              }
              
              //rSum
              if (rSum->TaintsReturnValue) {
                infoflow->setReachPtrTainted(srcKind, *ci);
              }
              
              for (unsigned ArgIndex = 0;
                   ArgIndex < rSum->NumArguments;
                   ++ArgIndex) {
                
                if (rSum->TaintsArgument[ArgIndex]) {
                  infoflow->setReachPtrTainted(srcKind, *(ci->getOperand(ArgIndex)));
                }
              }
              
              //trace-back to confirm infoflow with forward slicing
              //explicit-flow and cutAfterSinks.
              InfoflowSolution* fsoln =
              infoflow->leastSolution(kinds, false, true);
              
              Function* sinkFunc = sinkCI->getCalledFunction();
              if(sinkFunc->getName() == "__ioc_report_conversion") {
                if (checkForwardTainted(*(sinkCI->getOperand(7)), fsoln)) {
                  //tainted source detected! just get out
                  return false;
                }
              } else if (sinkFunc->getName() == "__ioc_report_add_overflow" ||
                         sinkFunc->getName() == "__ioc_report_sub_overflow" ||
                         sinkFunc->getName() == "__ioc_report_mul_overflow")
              {
                if (checkForwardTainted(*(sinkCI->getOperand(4)), fsoln) ||
                    checkForwardTainted(*(sinkCI->getOperand(5)), fsoln))
                {
                  return false;
                }
              } else {
                assert(false && "not __ioc_report function");
              }
            }
          }
        }
      }
    }
  }
  return ret;
}

bool
InfoAppPass::checkBackwardTainted(Value &V, InfoflowSolution* soln, bool direct)
{
  bool ret = (!soln->isTainted(V));
  
  if (direct) {
    ret = ret || (!soln->isDirectPtrTainted(V));
#ifdef __REACH__
    // XXX: not sure about Reachable pointer sets.
    ret = || (!soln->isReachPtrTainted(V));
#endif
  }

  return ret;
}
  
bool
InfoAppPass::checkForwardTainted(Value &V, InfoflowSolution* soln, bool direct)
{
  bool ret = (soln->isTainted(V));

  if (direct) {
    ret = ret || (soln->isDirectPtrTainted(V));
#ifdef __REACH__
    // XXX: not sure about Reachable pointer sets.
    ret = || (soln->isReachPtrTainted(V));
#endif
  }
  
  return ret;
}

bool
InfoAppPass::isConstAssign(const std::set<const Value *> vMap) {
  std::set<const Value *>::const_iterator vi = vMap.begin();
  std::set<const Value *>::const_iterator ve = vMap.end();

  for (;vi!=ve; vi++) {
    Value* val = (Value*) *vi;
    if (CallInst* ci = dyn_cast<CallInst>(val)) {
      Function* func = ci->getCalledFunction();
      if (func->getName().startswith("llvm.ssub.with.overflow")) {
        continue;
      } else {
        //XXX: need more for other function calls
      }
    } else if (dyn_cast<LoadInst>(val)) {
      return false;
    } else {
        //XXX: need more for other instructions
    }
  }
  return true;
}

}  //namespace deps

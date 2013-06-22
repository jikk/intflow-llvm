#include <sstream>

#include "llvm/Instruction.h"
#include "llvm/Instructions.h"
#include "llvm/Function.h"
#include "llvm/Module.h"
#include "llvm/Support/Debug.h"

#include "Infoflow.h"
#include "Slice.h"

#include "infoapp.h"
//#define __REACH__

using std::set;

namespace deps {

using namespace llvm;
  
  static void format_ioc_report_func(const Value* val, raw_string_ostream& rs) {
  
  const CallInst* ci = dyn_cast<CallInst>(val);
  assert(ci && "CallInst casting check");
  const Function* func = ci->getCalledFunction();
  assert(ci && "Function casting check");
  
  //line & column
  ConstantInt* line = dyn_cast<ConstantInt>(ci->getOperand(0));
  assert(line && "constant int casting check");
  
  ConstantInt* col = dyn_cast<ConstantInt>(ci->getOperand(1));
  assert(col && "constant int casting check");

  rs << func->getName().str();

  // XXX: how can i output char string?
  //ci->getOperand(2)->print(rs);
  rs << " (line ";
  rs << line->getZExtValue();
  rs << ", col ";
  rs << col->getZExtValue() << ")";
    

  if (func->getName() == "__ioc_report_add_overflow" ||
      func->getName() == "__ioc_report_sub_overflow" ||
      func->getName() == "__ioc_report_mul_overflow")
  {
    ;
  } else if (func->getName() == "__ioc_report_conversion") {
    ;
  } else {
    assert(! "invalid function name");
  }
}

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
  
//XXX: same function defined from SourceSinkAnalysis
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
    std::string output;
    raw_string_ostream rs(output);
    format_ioc_report_func(xi->first, rs);
    
    //changed ones
    errs() << "[InfoApp]xformMap:" << xi->second << ":";
    errs() << rs.str();
    errs() << "\n";
  }
}

bool
InfoAppPass::runOnModule(Module &M) {
  //assigning unique IDs to each overflow locations.
  static uint64_t unique_id = 0;

  doInitialization();

  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    //XXX: implement something here ..
    if (F.getName() == "") {
      //removeChecksForFunction(F);
      continue;
    }
    
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
          //XXX: implement from here
          } else if (func->getName() == "") {
            //XXX: lldiv, div, iconv ...
            ;
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
                
                if (dSum->TaintsArgument[ArgIndex]) {
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
                  DEBUG(errs() << "[InfoApp]checkForwardTainted:white0: true\n");
                  ret = true;
                } else {
                  DEBUG(errs() << "[InfoApp]checkForwardTainted:white0: false\n");
                  ret = false;
                }

              } else if (sinkFunc->getName() == "__ioc_report_add_overflow" ||
                         sinkFunc->getName() == "__ioc_report_sub_overflow" ||
                         sinkFunc->getName() == "__ioc_report_mul_overflow")
              {
                if (checkForwardTainted(*(sinkCI->getOperand(4)), fsoln) ||
                    checkForwardTainted(*(sinkCI->getOperand(5)), fsoln)) {
                  DEBUG(errs() << "[InfoApp]checkForwardTainted:white1: true\n");
                  ret = true;
                } else {
                  DEBUG(errs() << "[InfoApp]checkForwardTainted:white1: false\n");
                  ret = false;
                }

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

                if (dSum->TaintsArgument[ArgIndex]) {
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
                  DEBUG(errs() << "[InfoApp]checkForwardTainted:black0: true\n");
                  //tainted source detected! just get out
                  return false;
                } else {
                  DEBUG(errs() << "[InfoApp]checkForwardTainted:black0: false\n");
                }
                
              } else if (sinkFunc->getName() == "__ioc_report_add_overflow" ||
                         sinkFunc->getName() == "__ioc_report_sub_overflow" ||
                         sinkFunc->getName() == "__ioc_report_mul_overflow")
              {
                if (checkForwardTainted(*(sinkCI->getOperand(4)), fsoln) ||
                    checkForwardTainted(*(sinkCI->getOperand(5)), fsoln))
                {
                  DEBUG(errs() << "[InfoApp]checkForwardTainted:black1: true\n");
                  return false;
                } else {
                  DEBUG(errs() << "[InfoApp]checkForwardTainted:black1: false\n");
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
    const Value* val = (const Value*) *vi;
    if (const CallInst* ci = dyn_cast<const CallInst>(val)) {
      Function* func = ci->getCalledFunction();
      if (func->getName().startswith("llvm.ssub.with.overflow")) {
        continue;
      } else {
        //XXX: need more for other function calls
      }
    } else if (dyn_cast<const LoadInst>(val)) {
      return false;
    } else {
        //XXX: need more for other instructions
    }
  }
  return true;
}

}  //namespace deps

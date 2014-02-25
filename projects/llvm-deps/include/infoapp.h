#ifndef INFOAPP_H_
#define INFOAPP_H_

#include "llvm/Pass.h"
#include "llvm/PassManager.h"
#include "llvm/Module.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "Infoflow.h"

#include <set>

#define WHITE_LIST	"/opt/stonesoup/etc/whitelist.files"
#define BLACK_LIST	"/opt/stonesoup/etc/blacklist.files"
#define MODE_FILE	"/opt/stonesoup/etc/mode"
#define WHITELISTING	1
#define BLACKLISTING	2
#define WHITE_SENSITIVE	3
#define	BLACK_SENSITIVE	4
#define MODE_MAX_NUM	4


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
    unsigned char mode;

    virtual void doInitializationAndRun(Module &M);
    virtual void doFinalizationWhitelisting();

    void runOnModuleWhitelisting(Module &M);
//    void runOnModuleBlacklisting(Module &M);

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
    void removeChecksForFunction(Function& F, Module& M);
    void format_ioc_report_func(const Value* val, raw_string_ostream& rs);
    uint64_t getIntFromVal(Value* val);
    uint64_t getColFromVal(Value* val);
    void getStringFromVal(Value* val, std::string& output);
    void getMode();

};  //class
  
typedef  struct {
  char* func;
  char* fname;
  bool conversion;
  bool overflow;
  bool shift;
} rmChecks;

typedef struct {
	std::string fname;
	bool taintRetval;
	std::vector<int> taintedArgs;
} blacklistEntry;

}  // nameapce

#endif

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
#define MODE_FILE	"/opt/stonesoup/etc/mode"
#define WHITELISTING	1
#define BLACKLISTING	2
#define SENSITIVE		3
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
	uint64_t unique_id;
    DenseMap<const Value*, bool> xformMap;
    std::set<StringRef> whiteSet;
    std::set<StringRef> blackSet;
    unsigned char mode;

    virtual void doInitializationAndRun(Module &M);
    virtual void doFinalization();

    void runOnModuleWhitelisting(Module &M);
    void runOnModuleBlacklisting(Module &M);
    void runOnModuleSensitive(Module &M);

    /// Traverse instructions from the module(M) and identify tainted
    /// instructions.
    /// if it returns true: tag it to replace it with dummy
    ///       returns false: do not change
  
	bool trackSoln(Module &M,
				   InfoflowSolution* soln,
				   CallInst* sinkCI,
				   std::string& kinds);
	bool trackSolnInst(CallInst *i,
					   Module &M,
					   CallInst *ci,
					   InfoflowSolution* soln,
					   std::string& s);
	void backwardSlicingBlacklisting(Module &M,
									 InfoflowSolution* fsoln,
									 CallInst* srcCI);

	void taintForward(std::string s,
					  CallInst *ci,
					  const CallTaintEntry *entry);
	
	void taintBackwards(std::string s,
						CallInst *ci,
						const CallTaintEntry *entry);

	InfoflowSolution *forwardSlicingBlacklisting(CallInst *ci,
												 const CallTaintEntry *entry,
												 uint64_t *id);

	InfoflowSolution *getForwardSol(std::string s,
										  CallInst *ci,
										  const CallTaintEntry *entry);
	InfoflowSolution *getBackSolArithm(std::string s, CallInst *ci);
	InfoflowSolution *getForwSolArithm(std::string s, CallInst *ci);
	InfoflowSolution *getForwSolConv(std::string s, CallInst *ci);
	InfoflowSolution *getBackSolConv(std::string s, CallInst *ci);
	
    
	void removeBenignChecks(Module &M);
    void checkfTainted(Module &M, InfoflowSolution *f);
	void setWrapper(CallInst *ci, Module &M, Function *f);
	
	bool ioc_report_all_but_conv(std::string s);
	bool ioc_report_all(std::string s);
	bool ioc_report_arithm(std::string s);
	bool ioc_report_shl(std::string s);
    
	bool checkBackwardTainted(Value &V,
							  InfoflowSolution* soln,
							  bool direct=true);
    bool checkForwardTainted(Value &V,
							 InfoflowSolution* soln,
							 bool direct=true);
    bool isConstAssign(const std::set<const Value *> vMap);
    
	void removeChecksForFunction(Function& F, Module& M);
    void removeChecksInst(CallInst *i, unsigned int m, Module &M);
    void format_ioc_report_func(const Value* val, raw_string_ostream& rs);
    
    void getStringFromVal(Value* val, std::string& output);
    void getMode();
	uint64_t getIntFromVal(Value* val);
    uint64_t getColFromVal(Value* val);
	std::string getKindId(std::string name, uint64_t *id);

};  //class
  
typedef  struct {
  char* func;
  char* fname;
  bool conversion;
  bool overflow;
  bool shift;
} rmChecks;

void dbg_err(std::string s);
void dbg_msg(std::string s, std::string b);
}  // nameapce

#endif

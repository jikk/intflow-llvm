#include <sstream>
#include <fstream>
#include <string>
#include <vector>

#include "llvm/Instruction.h"
#include "llvm/Instructions.h"
#include "llvm/Function.h"
#include "llvm/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "llvm/GlobalVariable.h"
#include "llvm/Constants.h"

#include "Infoflow.h"
#include "Slice.h"

#include "infoapp.h"
//#define __REACH__

//#define __DBG__
#define DBG_LINE 322
#define DBG_COL 23

using std::set;

using namespace llvm;
using namespace deps;

static void getWhiteList();

namespace {

static rmChecks *rmCheckList;

static const struct CallTaintEntry bLstSourceSummaries[] = {
	// function  tainted values   tainted direct memory tainted root ptrs
	{ "fgets",   TAINTS_RETURN_VAL,  TAINTS_ARG_1,      TAINTS_NOTHING },
	{ "getchar", TAINTS_RETURN_VAL,  TAINTS_NOTHING,    TAINTS_NOTHING },
	{ "_IO_getc",TAINTS_RETURN_VAL,  TAINTS_NOTHING,    TAINTS_NOTHING },
	{ 0,         TAINTS_NOTHING,     TAINTS_NOTHING,    TAINTS_NOTHING }
};

static const struct CallTaintEntry wLstSourceSummaries[] = {
	// function  tainted values   tainted direct memory tainted root ptrs
	{ "gettimeofday",   TAINTS_RETURN_VAL,  TAINTS_ARG_1,      TAINTS_NOTHING },
	{ 0,                TAINTS_NOTHING,     TAINTS_NOTHING,    TAINTS_NOTHING }
};

static const struct CallTaintEntry sensSinkSummaries[] = {
	// function  tainted values   tainted direct memory tainted root ptrs
	{ "malloc",   	TAINTS_ARG_1,  	TAINTS_NOTHING,    	TAINTS_NOTHING },
	{ "calloc",  TAINTS_ALL_ARGS,  	TAINTS_NOTHING,    	TAINTS_NOTHING },
	{ "realloc", TAINTS_ALL_ARGS,	TAINTS_NOTHING,    	TAINTS_NOTHING },
	{ 0,          TAINTS_NOTHING,	TAINTS_NOTHING,		TAINTS_NOTHING }
};

CallTaintEntry nothing = { 0, TAINTS_NOTHING, TAINTS_NOTHING, TAINTS_NOTHING };




/* ****************************************************************************
 * ============================================================================
 *  				    Pass Initialization & Fin Functions
 * ============================================================================
 * ****************************************************************************/

bool
InfoAppPass::runOnModule(Module &M)
{
	doInitializationAndRun(M);
	return false;
}

void
InfoAppPass::doInitializationAndRun(Module &M)
{
	unique_id = 0;
	infoflow = &getAnalysis<Infoflow>();
	getWhiteList();
	getMode();
	
	if (mode == WHITELISTING) {
		dbg_err("WhiteListing");
		runOnModuleWhitelisting(M);
	}
	else if (mode == BLACKLISTING){
		dbg_err("BlackListing");
		runOnModuleBlacklisting(M);
	}
	else if (mode == SENSITIVE) {
		dbg_err("Sensitive");
		runTest(M);
		//runOnModuleSensitive(M);
	}
	else if (mode == BLACK_SENSITIVE) {
		/* TODO: to be added */
		;
	}
	else
		exit(mode);
	
	//doFinalization();
}

void
InfoAppPass::doFinalization() {
	dbg_err("doFinalizationWhitelisting");
	DenseMap<const Value*, bool>::const_iterator xi = xformMap.begin();
	DenseMap<const Value*, bool>::const_iterator xe = xformMap.end();

	for (;xi!=xe; xi++) {
		std::string output;
		raw_string_ostream rs(output);
		if (xi->second) {
			format_ioc_report_func(xi->first, rs);
			dbg_msg("[InfoApp]xformMap:", xi->second + ":" + rs.str());
		}
	}
	
	for (unsigned i=0; rmCheckList[i].func; i++) {
		delete rmCheckList[i].func;
		delete rmCheckList[i].fname;
	}
	
	delete rmCheckList;
}

/* ****************************************************************************
 * ============================================================================
 *  						Taint Functions
 * ============================================================================
 * ****************************************************************************/

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
InfoAppPass::taintForward(std::string srcKind,
						  CallInst *ci,
						  const CallTaintEntry *entry)
{
	const CallTaintSummary *vSum = &(entry->ValueSummary);
	const CallTaintSummary *dSum = &(entry->DirectPointerSummary);
	const CallTaintSummary *rSum = &(entry->RootPointerSummary);
	
	/* vsum */
	if (vSum->TaintsReturnValue)
		infoflow->setTainted(srcKind, *ci);

	for (unsigned ArgIndex = 0; ArgIndex < vSum->NumArguments; ++ArgIndex) {
		if (vSum->TaintsArgument[ArgIndex])
			infoflow->setTainted(srcKind, *(ci->getOperand(ArgIndex)));
	}

	/* dsum */
	if (dSum->TaintsReturnValue)
		infoflow->setDirectPtrTainted(srcKind, *ci);

	for (unsigned ArgIndex = 0; ArgIndex < dSum->NumArguments; ++ArgIndex) {
		if (dSum->TaintsArgument[ArgIndex])
			infoflow->setDirectPtrTainted(srcKind, *(ci->getOperand(ArgIndex)));
	}

	/* rsum */
	if (rSum->TaintsReturnValue)
		infoflow->setReachPtrTainted(srcKind, *ci);

	for (unsigned ArgIndex = 0; ArgIndex < rSum->NumArguments; ++ArgIndex) {
		if (rSum->TaintsArgument[ArgIndex])
			infoflow->setReachPtrTainted(srcKind, *(ci->getOperand(ArgIndex)));
	}
}

void
InfoAppPass::taintBackwards(std::string sinkKind,
							CallInst *ci,
							const CallTaintEntry *entry)
{
	const CallTaintSummary *vSum = &(entry->ValueSummary);
	const CallTaintSummary *dSum = &(entry->DirectPointerSummary);
	const CallTaintSummary *rSum = &(entry->RootPointerSummary);
	
	/* vsum */
	if (vSum->TaintsReturnValue)
		infoflow->setUntainted(sinkKind, *ci);

	for (unsigned ArgIndex = 0; ArgIndex < vSum->NumArguments; ++ArgIndex) {
		if (vSum->TaintsArgument[ArgIndex])
			infoflow->setUntainted(sinkKind, *(ci->getOperand(ArgIndex)));
	}

	/* dsum */
	if (dSum->TaintsReturnValue)
		infoflow->setDirectPtrUntainted(sinkKind, *ci);

	for (unsigned ArgIndex = 0; ArgIndex < dSum->NumArguments; ++ArgIndex) {
		if (dSum->TaintsArgument[ArgIndex])
			infoflow->setDirectPtrUntainted(sinkKind,
											*(ci->getOperand(ArgIndex)));
	}

	/* rsum */
	if (rSum->TaintsReturnValue)
		infoflow->setReachPtrUntainted(sinkKind, *ci);

	for (unsigned ArgIndex = 0; ArgIndex < rSum->NumArguments; ++ArgIndex) {
		if (rSum->TaintsArgument[ArgIndex])
			infoflow->setReachPtrUntainted(sinkKind,
										   *(ci->getOperand(ArgIndex)));
	}
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



/* ****************************************************************************
 * ============================================================================
 *  							IntFlow Modes
 * ============================================================================
 * ****************************************************************************/

void
InfoAppPass::runOnModuleWhitelisting(Module &M)
{
	for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
		Function& F = *mi;
		
		dbg_msg("DBG0:fname:", F.getName());
		removeChecksForFunction(F, M);

		for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
			BasicBlock& B = *bi;
			for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
				if (CallInst* ci = dyn_cast<CallInst>(ii)) {

					Function* func = ci->getCalledFunction();
					if (!func)
						continue;
					
					if (ioc_report_all_but_conv(func->getName())) {
#ifdef __DBG__
						uint32_t line = getIntFromVal(ci->getOperand(0));
						uint32_t col  = getIntFromVal(ci->getOperand(1));

						if (line != DBG_LINE || col != DBG_COL)
							continue;
#endif

						//check for arg. count
						assert(ci->getNumOperands() == 8);
						
						std::stringstream ss;
						ss << ci->getNumOperands();
						
						dbg_msg("numOper:", ss.str());
						dbg_msg("func_name:", func->getName());
						
						std::string sinkKind = getKindId("arithm",
														 &unique_id);
						InfoflowSolution* soln = 
							getBackSolArithm(sinkKind, ci);
						
						//check for simple const. assignment
						//getting valeMap
						std::set<const Value *> vMap;
						soln->getValueMap(vMap);

						if(isConstAssign(vMap)) {
							//replace it for simple const. assignment
							dbg_err("isConstAssign0:true");
							xformMap[ci] = true;
						} else {
							xformMap[ci] = trackSoln(M, soln, ci, sinkKind);
						}

						if (xformMap[ci]) {
							setWrapper(ci, M, func);
							//if (theofilos(M, ci) ) {
						}
					} else if (func->getName() == "__ioc_report_conversion") {
						//check for arg. count
						assert(ci->getNumOperands() == 10);

#ifdef __DBG__
						uint32_t line = getIntFromVal(ci->getOperand(0));
						uint32_t col  = getIntFromVal(ci->getOperand(1));

						if (line != DBG_LINE || col != DBG_COL)
							continue;
#endif

						std::string sinkKind = getKindId("conv",
														&unique_id);
						InfoflowSolution* soln = getBackSolConv(sinkKind, ci);

						//check for simple const. assignment
						std::set<const Value *> vMap;
						soln->getValueMap(vMap);

						if(isConstAssign(vMap))
						{
							//replace it for simple const. assignment
							dbg_err("isConstAssign1:true");
							xformMap[ci] = true;

						} else {
							xformMap[ci] = trackSoln(M, soln, ci, sinkKind);
						}

						if (xformMap[ci]) {
							//theofilos check 
							setWrapper(ci, M, func);
						}
					} else if ((func->getName() == "div")   ||
							   (func->getName() == "ldiv")  ||
							   (func->getName() == "lldiv") ||
							   (func->getName() == "iconv")
							  ) {
						setWrapper(ci, M, func);
					}
				}
			}
		}
	}
}

void
InfoAppPass::runTest(Module &M)
{
	uint64_t arr_n = 5;
	uint64_t ioc_cnt = 1;
	Function *func;
	iplist<GlobalVariable>::iterator gvIt;
	//Do a first pass and count ioc and sens entries
	for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
		Function& F = *mi;
		for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
			BasicBlock& B = *bi;
			for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {

				if (CallInst* ci = dyn_cast<CallInst>(ii)) {

					func = ci->getCalledFunction();
					if (!func)
						continue;

					const CallTaintEntry *entry =
						findEntryForFunction(sensSinkSummaries,
											 func->getName());
					if (entry->Name) {

						//find basic block of sensitive
						BasicBlock *bb = ii->getParent();
						std::string sinkKind = bb->getName();

						/* Initialize malloc array */
						//FIXME replace with ioc_cnt
						ArrayType* intPtr = ArrayType::get(IntegerType::get(M.getContext(), 32), arr_n);

						GlobalVariable* iocArray = new GlobalVariable(/*Module=*/M, 
																	  /*Type=*/intPtr,
																	  /*isConstant=*/false,
																	  /*Linkage=*/GlobalValue::ExternalLinkage,
																	  /*Initializer=*/0, // has initializer, specified below
																	  /*Name=*/"__gl_ioc_malloc_" + sinkKind);
						iocArray->setAlignment(8);
						std::vector<Constant*> Initializer;
						Initializer.reserve(arr_n);
						Constant* zero = ConstantInt::get(IntegerType::get(M.getContext(), 32), 0);

						for (uint64_t i = 0; i < arr_n; i++) {
							Initializer[i++] = zero; 
						}

						ArrayType *ATy = ArrayType::get(IntegerType::get(M.getContext(), 32), arr_n);
						Constant *initAr = llvm::ConstantArray::get(ATy, Initializer); 
						iocArray->setInitializer(initAr);

						for (gvIt = M.global_begin(); gvIt != M.global_end(); gvIt++)
							if ( gvIt->getName().str() == "__gl_ioc_malloc_" + sinkKind) {
								dbg_msg("GLOBAL:", gvIt->getName().str());
								GlobalVariable *tmpgl = gvIt;


								/* 
								 *
								 * Add function to get address of this
								 * Global Variable (separate BB)
								 *
								 */
								PointerType* arrayPtr = PointerType::get(IntegerType::get(M.getContext(), 32), 0);

								std::vector<Type*>FuncTy_args;
								FuncTy_args.push_back(IntegerType::get(M.getContext(), 32));
								FunctionType* FuncTy = FunctionType::get(
												/*Result=*/IntegerType::get(M.getContext(), 32),
												/*Params=*/FuncTy_args,
												/*isVarArg=*/false);

								Function* func_foo = M.getFunction("getEntry_" + sinkKind);
								if (!func_foo) {
									func_foo = Function::Create(
													/*Type=*/FuncTy,
													/*Linkage=*/GlobalValue::ExternalLinkage,
													/*Name=*/"getEntry_" + sinkKind, &M); 
									func_foo->setCallingConv(CallingConv::C);
								}

								Function::arg_iterator args = func_foo->arg_begin();
								Value* int32_c = args++;
								int32_c->setName("c");

								BasicBlock* label_entry = BasicBlock::Create(M.getContext(), "entry",func_foo,0);

								CastInst* int64_idxprom = new SExtInst(int32_c, IntegerType::get(M.getContext(), 64), "idxprom", label_entry);
								std::vector<Value*> ptr_arrayidx_indices;

								ConstantInt* const_int64_6 = ConstantInt::get(M.getContext(), APInt(64, StringRef("0"), 10));
								ptr_arrayidx_indices.push_back(const_int64_6);
								ptr_arrayidx_indices.push_back(int64_idxprom);

								GetElementPtrInst* ptr_arrayidx = GetElementPtrInst::Create(tmpgl, ptr_arrayidx_indices, "arrayidx", label_entry);
								LoadInst* int32_5 = new LoadInst(ptr_arrayidx, "", false, label_entry);
								int32_5->setAlignment(4);
								ReturnInst::Create(M.getContext(), int32_5, label_entry);
								
								
								/*
								 *
								 * Function to check if ioc overflowed
								 *
								 */
								Function *f;
								Instruction *injIns;
								//argument just needed for string
								Constant *fc = M.getOrInsertFunction("checkIoc", //name
																	 Type::getInt32Ty(M.getContext()), //function type
																	 arrayPtr,
																	 Type::getInt32Ty(M.getContext()),//position variable
																	 /*Linkage=*/GlobalValue::ExternalLinkage,
																	 (Type *)0);
								std::vector<Value *> fargs;
								fargs.push_back(ptr_arrayidx);       
								fargs.push_back(ConstantInt::get(M.getContext(), APInt(32, ioc_cnt)));       

								f = cast<Function>(fc);
								ArrayRef<Value *> functionArguments(fargs);
								injIns = CallInst::Create(f, functionArguments, "");
								ci->getParent()->getInstList().insert(ci, injIns);
								
								//create bb for functions
								BasicBlock *bb = ci->getParent();
						  		BasicBlock *bb_after = ci->getParent()->splitBasicBlock(ci);
								bb->getTerminator()->eraseFromParent(); 
 // Get pointers to the constants.
      Value *Zero = ConstantInt::get(Type::getInt32Ty(M.getContext()), 0);

      /* set the predicate according to the value of trueOrFalse */
      ICmpInst::Predicate predicate;
	  predicate = ICmpInst::ICMP_EQ;

      //IN LLVM the instruction is itself the result. Check 
      //http://comments.gmane.org/gmane.comp.compilers.llvm.devel/49672
      ICmpInst *CondInst = new ICmpInst(*bb,
          predicate,
          injIns,
          Zero,
          "cond");

      BasicBlock *BB = BasicBlock::Create(M.getContext(),
          "malloc_ioc_exit",
          ci->getParent()->getParent());

      BranchInst::Create(bb_after, BB, CondInst, bb);								

#if 0
								/*
								 *
								 * call getEntry
								 *
								 */
								std::vector<Value *> cargs;
								Function* fentry = M.getFunction("getEntry_" + sinkKind);
								if (!fentry)
									dbg_msg("ERROR:", "could not get entry");
								cargs.push_back(ConstantInt::get(M.getContext(), APInt(32, ioc_cnt)));       
								ArrayRef<Value *> funArguments(cargs);
								CallInst *geIns = CallInst::Create(fentry, funArguments, "", bb);
								geIns->setCallingConv(CallingConv::C);
								geIns->setTailCall(false);
#endif
if (mi->getReturnType()->isVoidTy())
          ReturnInst::Create(M.getContext(), BB);
      else //for now only support void & number return types
        ReturnInst::Create(M.getContext(), Zero, BB);
return;
							}
					}
				} 
			}
		}
	}
}
/* 
 * ===  FUNCTION  =============================================================
 *         Name:  runOnModuleSensitive
 *    Arguments:  @M - The source code module
 *  Description:  Implements InfoAppPass For Sensitive Sinks.
 *  		      Removes the checks from every operation unless this 
 *  			  operation's result is used in a sensitive sink. Sinks are 
 *  			  identified after first implementing a forward analysis 
 *  			  and then a and backward slicing. 
 * ============================================================================
 */
void
InfoAppPass::runOnModuleSensitive(Module &M)
{
	Function *func;
	uint64_t ioc_cnt  = 0;

	//Do a first pass and count ioc and sens entries
	for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
		Function& F = *mi;
		for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
			BasicBlock& B = *bi;
			for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {

				if (CallInst* ci = dyn_cast<CallInst>(ii)) {

					func = ci->getCalledFunction();
					if (!func)
						continue;

					if (ioc_report_all(func->getName())) {
						ioc_cnt++;
					}
				}
			} /* for-loops close here*/
		}
	}

	uint64_t tmp_cnt  = 0;
	iocIdName = new std::string[ioc_cnt];

#if 0	
	//FIXME remove this
	std::stringstream SS;
	SS << ioc_cnt;
	dbg_msg("ioc total", SS.str());
#endif

	for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
		Function& F = *mi;
		removeChecksForFunction(F, M);
		for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
			BasicBlock& B = *bi;
			for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {

				if (CallInst* ci = dyn_cast<CallInst>(ii)) {

					func = ci->getCalledFunction();
					if (!func)
						continue;

					if (ioc_report_all(func->getName())) {
						//FIXME create a table globally
						//(can we do better?)
						BasicBlock *bb = ii->getParent();
						iocIdName[tmp_cnt++] = bb->getName();
					}

					const CallTaintEntry *entry =
						findEntryForFunction(sensSinkSummaries,
											 func->getName());
					if (entry->Name) {
						dbg_msg("sens: ", entry->Name);

						//find malloc basic block
						BasicBlock *bb = ii->getParent();
						dbg_msg("bb is", bb->getName());
						
						std::string sinkKind = bb->getName();
						InfoflowSolution *soln = getBackwardsSol(sinkKind,
																 ci,
																 entry);

						std::set<const Value *> vMap;
						soln->getValueMap(vMap);

						if(isConstAssign(vMap))
						{
							/* we want to keep those */
							dbg_err("sens-const");
							xformMap[ci] = true;

						} else {

		//Add function to malloc
		std::vector<Value *> args;
		Function *f;
		Instruction *injIns;
		args.push_back(ConstantInt::get(M.getContext(), APInt(32, 0)));
        
		Constant *fc = M.getOrInsertFunction("xorIocBlocks", //name
                        Type::getInt32Ty(M.getContext()), //type
						//args
                        Type::getInt32Ty(M.getContext()),
                        (Type *)0);
        f = cast<Function>(fc);
        ArrayRef<Value *> functionArguments(args);
        injIns = CallInst::Create(f, functionArguments, "");
        ci->getParent()->getInstList().insert(ci, injIns);
	
							iocPoints[sinkKind] = std::vector<iocPoint>();
							//check forward
							trackSoln(M, soln, ci, sinkKind);
						}
					} else if ((func->getName() == "div")   ||
							   (func->getName() == "ldiv")  ||
							   (func->getName() == "lldiv") ||
							   (func->getName() == "iconv")) {
						setWrapper(ci, M, func);
					}
				}
			} /* for-loops close here*/
		}
	}
	
	removeBenignChecks(M);
}

/* 
 * ===  FUNCTION  =============================================================
 *         Name:  runOnModuleBlacklisting
 *    Arguments:  @M - The source code module
 *  Description:  Implements InfoAppPass Blacklisting. Removes the checks from
 *  		  every operation unless this operation is identified as
 *  		  untrusted after forward (implemented here) and backward slicing
 *  		  (implemented in trackSinks).
 *  		  Untrusted sources are defined at bLstSourceSummaries.
 *  		  It also uses the whitelist provided at WHITE_LIST in order to
 *  		  remove manually identified benign operations.
 * ============================================================================
 */
void
InfoAppPass::runOnModuleBlacklisting(Module &M)
{
	Function *func;
	InfoflowSolution *fsoln;

	for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
		Function& F = *mi;
		dbg_msg("DBG0:fname:", F.getName());
		//this is for whitelisting
		removeChecksForFunction(F, M);
		for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
			BasicBlock& B = *bi;
			for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {

				if (CallInst* ci = dyn_cast<CallInst>(ii)) {
					func = ci->getCalledFunction();
					if (!func)
						continue;
					const CallTaintEntry *entry =
						findEntryForFunction(bLstSourceSummaries,
											 func->getName());
					if (entry->Name) {
#ifdef __DBG__
						uint32_t line = getIntFromVal(ci->getOperand(0));
						uint32_t col = getIntFromVal(ci->getOperand(1));
						if (line != DBG_LINE || col != DBG_COL)
							continue;
#endif
						std::string srcKind = getKindId("src", &unique_id);
						fsoln = getForwardSol(srcKind, ci, entry);

						backwardSlicingBlacklisting(M, fsoln, ci);
					}  else if ((func->getName() == "div")   ||
								(func->getName() == "ldiv")  ||
								(func->getName() == "lldiv") ||
								(func->getName() == "iconv")) {
						/* these need to be handled anyway */
						setWrapper(ci, M, func);
					}
				}
			} /* for-loops close here*/
		}
	}
	/* now xformMap holds all the information  */
	removeBenignChecks(M);
}

void
InfoAppPass::backwardSlicingBlacklisting(Module &M,
										InfoflowSolution* fsoln,
										CallInst* srcCI)
{
	Function *func;
	for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
		Function& F = *mi;
		dbg_msg("DBG0:fname:", F.getName());
		for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
			BasicBlock& B = *bi;
			for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
				if (CallInst* ci = dyn_cast<CallInst>(ii)) {
					if (xformMap[ci])
						continue;
					
					func = ci->getCalledFunction();
					if (func->getName() == "__ioc_report_conversion") {
						xformMap[ci] = false;
						
						// this checks if it is tainted
						if (checkForwardTainted(*(ci->getOperand(7)), fsoln)) {
							//check for arg. count
							assert(ci->getNumOperands() == 10);
							
							//this returns all sources that are tainted
							std::string sinkKind   = getKindId("conv",
															   &unique_id);

							InfoflowSolution *soln = getBackSolConv(sinkKind,
																	ci);

							//check if source is in our list
							if (checkBackwardTainted(*srcCI, soln))
								xformMap[ci] = true;
						}
					
					} else if (ioc_report_all_but_conv(func->getName())) {
						xformMap[ci] = false;
						if (checkForwardTainted(*(ci->getOperand(4)), fsoln) ||
							checkForwardTainted(*(ci->getOperand(5)), fsoln)) {
							
							std::string sinkKind   = getKindId("arithm",
															   &unique_id);
							InfoflowSolution *soln =
								getBackSolArithm(sinkKind, ci);
							
							/* check if srcCI is backward tainted */
							if (checkBackwardTainted(*srcCI, soln))
								xformMap[ci] = true;
						}
					}
				}
			}
		}
	}
}

/* ****************************************************************************
 * ============================================================================
 *  					Functions Removing IOC stuff
 * ============================================================================
 * ****************************************************************************/

/* 
 * ===  FUNCTION  =============================================================
 *         Name:  removeBenignChecks
 *    Arguments:  @M - the source code module
 *  Description:  Iterates over the module and checks how every call instruction
 *  			  If this instruction is noted as trusted (xformMap has a false
 *  			  value), then we remove the checks.
 * ============================================================================
 */
void
InfoAppPass::removeBenignChecks(Module &M)
{
	for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
		Function& F = *mi;
		for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
			BasicBlock& B = *bi;
			for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
				if (CallInst* ci = dyn_cast<CallInst>(ii)) {
					Function *func = ci->getCalledFunction();
					if (ioc_report_all(func->getName()) && !xformMap[ci] ){
						setWrapper(ci, M, func);
					}
				}
			}
		}
	}
}

void
InfoAppPass::removeChecksForFunction(Function& F, Module& M) {
	for (unsigned i=0; rmCheckList[i].func; i++) {
		if (F.getName() == rmCheckList[i].func) {
			for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
				BasicBlock& B = *bi;
				for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
					if (CallInst* ci = dyn_cast<CallInst>(ii))
						removeChecksInst(ci, i, M);
				}
			}
		}
	}
}

void
InfoAppPass::removeChecksInst(CallInst *ci, unsigned int i, Module &M)
{
	Function* f = ci->getCalledFunction();
	if (!f)
		return;
	
	std::string fname = f->getName();
	
	if (
		/* remove overflow */
		(rmCheckList[i].overflow && ioc_report_arithm(fname)) 				||
		/* remove conversion */
		(rmCheckList[i].conversion && (fname == "__ioc_report_conversion")) ||
		/* remove shift */
		(rmCheckList[i].shift && ioc_report_shl(fname))) {
			xformMap[ci] = true;
			setWrapper(ci, M, f);
	}
}

/* ****************************************************************************
 * ============================================================================
 *  						Solution Functions
 * ============================================================================
 * ****************************************************************************/

InfoflowSolution *
InfoAppPass::getForwardSol(std::string srcKind,
								 CallInst *ci,
								 const CallTaintEntry *entry)
{
	
	//XXX Do not change order
	taintForward(srcKind, ci, entry);
	
	std::set<std::string> kinds;
	kinds.insert(srcKind);
	
	//This does forward analysis
	InfoflowSolution *fsoln = infoflow->leastSolution(kinds, false, true);

	return fsoln;
}

InfoflowSolution *
InfoAppPass::getBackwardsSol(std::string sinkKind,
							 CallInst *ci,
							 const CallTaintEntry *entry)
{
	
	//XXX Do not change order
	taintBackwards(sinkKind, ci, entry);
	
	std::set<std::string> kinds;
	kinds.insert(sinkKind);
	
	InfoflowSolution *fsoln = infoflow->greatestSolution(kinds, false);

	return fsoln;
}

InfoflowSolution *
InfoAppPass::getForwSolArithm(std::string srcKind, CallInst *ci)
{
	Value* lval = ci->getOperand(4);
	Value* rval = ci->getOperand(5);

	//tagging lVal
	infoflow->setTainted(srcKind, *lval);
	
	//tagging rVal
	infoflow->setTainted(srcKind, *rval);

	std::set<std::string> kinds;
	kinds.insert(srcKind);
	
	return infoflow->leastSolution(kinds, false, true);
}

InfoflowSolution *
InfoAppPass::getBackSolArithm(std::string sinkKind, CallInst *ci)
{
	Value* lval = ci->getOperand(4);
	Value* rval = ci->getOperand(5);

	//tagging lVal
	infoflow->setUntainted(sinkKind, *lval);
	
	//tagging rVal
	infoflow->setUntainted(sinkKind, *rval);

	std::set<std::string> kinds;
	kinds.insert(sinkKind);
	
	return infoflow->greatestSolution(kinds, false);
}

InfoflowSolution *
InfoAppPass::getBackSolConv(std::string sinkKind, CallInst *ci)
{
	Value* val = ci->getOperand(7);
	infoflow->setUntainted(sinkKind, *val);
	
	std::set<std::string> kinds;
	kinds.insert(sinkKind);
	
	return infoflow->greatestSolution(kinds, false);
}

InfoflowSolution *
InfoAppPass::getForwSolConv(std::string srcKind, CallInst *ci)
{
	Value* val = ci->getOperand(7);
	infoflow->setTainted(srcKind, *val);
	
	std::set<std::string> kinds;
	kinds.insert(srcKind);
	
	return infoflow->leastSolution(kinds, false, true);
}


/* 
 * ===  FUNCTION  =============================================================
 *         Name:  trackSoln
 *    Arguments:  @M - the source code module
 *  Description:  TODO
 *  		
 * ============================================================================
 */
bool
InfoAppPass::trackSoln(Module &M,
		InfoflowSolution* soln,
		CallInst* sinkCI,
		std::string& kind)
{
	dbg_err("trackSoln");
	//by default do not change/replace.
	bool ret = false;
	
	//need optimization or parallelization
	for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
		Function& F = *mi;
		
		for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
			BasicBlock& B = *bi;
			for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
				if (checkBackwardTainted(*ii, soln)) {
					DEBUG(ii->dump());

					if (CallInst* ci = dyn_cast<CallInst>(ii)) {
						if (xformMap[ci])
							continue;
						ret = ret || trackSolnInst(ci, M, sinkCI, soln, kind);
					}
				}
			}
		}
	}
	return ret;
}

/* FIXME refactor */
/* 
 * ===  FUNCTION  =============================================================
 *         Name:  trackSolnInst
 *    Arguments:  @M - the source code module
 *    			TODO
 *  Description: checks first if each instruction in the solution is forward
 *  			tainted and returns true or false
 *  		
 * ============================================================================
 */
bool 
InfoAppPass::trackSolnInst(CallInst *ci,
						   Module &M,
						   CallInst* sinkCI,
						   InfoflowSolution* soln,
						   std::string& kind)
{
	bool ret = false;
	
	Function* func = ci->getCalledFunction();
	std::string fname = func->getName();

	//check for white-listing
	const CallTaintEntry *entry = findEntryForFunction(wLstSourceSummaries,
													   fname);
	if (entry->Name && mode == WHITELISTING) {
		dbg_msg("white-list:", fname);
		std::string srcKind = "src0" + kind;

		InfoflowSolution* fsoln = getForwardSol(srcKind, ci, entry);
		
		Function* sinkFunc = sinkCI->getCalledFunction();
		if(sinkFunc->getName() == "__ioc_report_conversion")
		{
			if (checkForwardTainted(*(sinkCI->getOperand(7)), fsoln)) {
				dbg_err("checkForwardTainted:white0:true");
				ret = true;
			} else {
				dbg_err("checkForwardTainted:white0:false");
				ret = false;
			}

		} else if (ioc_report_all_but_conv(sinkFunc->getName()))
		{
			if (checkForwardTainted(*(sinkCI->getOperand(4)), fsoln) ||
				checkForwardTainted(*(sinkCI->getOperand(5)), fsoln)) {
				dbg_err("checkForwardTainted:white1:true");
				ret = true;
			} else {
				dbg_err("checkForwardTainted:white1:false");
				ret = false;
			}

		} else {
			assert(false && "not __ioc_report function");
		}
	}

	entry = findEntryForFunction(bLstSourceSummaries, fname);

	if (entry->Name && mode == BLACKLISTING) {
		dbg_msg("black-list: ", fname);
		std::string srcKind = "src1" + kind;
		InfoflowSolution* fsoln = getForwardSol(srcKind, ci, entry);
		
		Function* sinkFunc = sinkCI->getCalledFunction();
		if(sinkFunc->getName() == "__ioc_report_conversion") {
			if (checkForwardTainted(*(sinkCI->getOperand(7)), fsoln)) {
				dbg_err("checkForwardTainted:black0:true");
				//tainted source detected! just get out
				return false;
			} else {
				dbg_err("checkForwardTainted:black0:false");
			}

		} else if (ioc_report_all_but_conv(sinkFunc->getName()))
		{
			if (checkForwardTainted(*(sinkCI->getOperand(4)), fsoln) ||
				checkForwardTainted(*(sinkCI->getOperand(5)), fsoln))
			{
				dbg_err("checkForwardTainted:black1:true");
				return false;
			} else {
				dbg_err("checkForwardTainted:black1:false");
			}
		} else {
			assert(false && "not __ioc_report function");
		}
	}

	if (StringRef(fname).startswith("__ioc") && mode == SENSITIVE) {
		
		//FIXME unique id for ioc src argument. This could be the BB?
		std::string srcKind = getKindId("sens-ioc",
										&unique_id);

		
		BasicBlock *ioc_bb = ci->getParent();
		iocPoint p;
		
		if (iocPoints[kind].empty()) {
			/* If not here, create and set to false */
			p[ioc_bb->getName()] = false;
			iocPoints[kind].push_back(p);
		} 

#if 0
		else {
			/* Else find re-set to false */
			for (iocPointsForSens::const_iterator ioc_p = iocPoints.begin();
				 ioc_p != iocPoints.end();
				 ++ioc_p) {

				iocPointVector ipv = ioc_p->second;
				for(iocPointVector::const_iterator ivi = ipv.begin();
					ivi != ipv.end();
					++ivi) {
					iocPoint point = *ivi;
					dbg_msg("resetting ",
							point.find(ioc_bb->getName())->first);
					point[ioc_bb->getName()] = false;
				}
			}
		}

		/*
		 * TODO
		 *
		 *
		 * Store basic block name in IRa
		 * insert function setting the map value to 1 in ioc_report
		 * insert function setting the map value to 0 in other bb
		 *
		 * insert map to IR. In main 
		 * insert function before malloc to check map values
		 *
		 *
		 * in case of full despair the plan is:
		 * we will keep an array containing the values of all ioc bb in every
		 * basic block and just update the corresponding value. 
		 */
#endif
		if(fname == "__ioc_report_conversion") {
			InfoflowSolution* fsoln = getForwSolConv(srcKind, ci);

			if (checkForwardTainted(*(ci->getOperand(7)), fsoln)) {
				dbg_err("checkForwardTainted:sens0:true");
				
				//FIXME remove this
				xformMap[ci] = true;

				//create mvar, add it to the set for this particular malloc
				//mvar = 1 inside the basic block
				//mvar = 0 inside the next basic block, so that the same
				//variable gets re-set if we don't go there.
				return true;
			} else {
				dbg_err("checkForwardTainted:sens0:false");
			}
		} else if (ioc_report_all_but_conv(fname)) {
			InfoflowSolution* fsoln = getForwSolArithm(srcKind, ci);
			
			if (checkForwardTainted(*(ci->getOperand(4)), fsoln) ||
				checkForwardTainted(*(ci->getOperand(5)), fsoln))
			{
				dbg_err("checkForwardTainted:sens1:true");
				xformMap[ci] = true;
				return true;
			} else {
				dbg_err("checkForwardTainted:sens1:false");
			}
		} else {
			assert(false && "not sensitive function");
		}
	}
	
	return ret;
}

/* ****************************************************************************
 * ============================================================================
 *  								CHECKS
 * ============================================================================
 * ****************************************************************************/

bool
InfoAppPass::isConstAssign(const std::set<const Value *> vMap) {
	std::set<const Value *>::const_iterator vi = vMap.begin();
	std::set<const Value *>::const_iterator ve = vMap.end();

	for (;vi!=ve; vi++) {
		const Value* val = (const Value*) *vi;
		if (const CallInst* ci = dyn_cast<const CallInst>(val)) {
			Function* func = ci->getCalledFunction();
			//assert(func && "func should be fine!");
			if (func && func->getName().startswith("llvm.ssub.with.overflow")) {
				continue;
			} else {
				//XXX: need more for other function calls
				dbg_msg("isConstAssign:", func->getName());
				return false;
			}
		} else if (dyn_cast<const LoadInst>(val)) {
			return false;
		} else {
			//XXX: need more for other instructions
		}
	}
	return true;
}

bool
InfoAppPass::ioc_report_all_but_conv(std::string name)
{
	return (name == "__ioc_report_add_overflow" ||
			name == "__ioc_report_sub_overflow" ||
			name == "__ioc_report_mul_overflow" ||
			name == "__ioc_report_shr_bitwidth" ||
			name == "__ioc_report_shl_bitwidth" ||
			name == "__ioc_report_shl_strict");
}

bool
InfoAppPass::ioc_report_all(std::string name)
{
	return (name == "__ioc_report_add_overflow" ||
			name == "__ioc_report_sub_overflow" ||
			name == "__ioc_report_mul_overflow" ||
			name == "__ioc_report_shr_bitwidth" ||
			name == "__ioc_report_shl_bitwidth" ||
			name == "__ioc_report_shl_strict"	||
			name == "__ioc_report_conversion");
}

bool
InfoAppPass::ioc_report_arithm(std::string name)
{
	return (name == "__ioc_report_add_overflow" ||
			name == "__ioc_report_sub_overflow" ||
			name == "__ioc_report_mul_overflow");
}

bool
InfoAppPass::ioc_report_shl(std::string name)
{
	return (name == "__ioc_report_shr_bitwidth" ||
			name == "__ioc_report_shl_bitwidth" ||
			name == "__ioc_report_shl_strict");
}


/* ****************************************************************************
 * ============================================================================
 *  							HELPER FUNCTIONS 
 * ============================================================================
 * ****************************************************************************/

uint64_t
InfoAppPass::getIntFromVal(Value* val)
{
	ConstantInt* num = dyn_cast<ConstantInt>(val);
	assert(num && "constant int casting check");
	return num->getZExtValue();
}

void
InfoAppPass::getStringFromVal(Value* val, std::string& output)
{
	Constant* gep = dyn_cast<Constant>(val);
	assert(gep && "assertion");
	GlobalVariable* global = dyn_cast<GlobalVariable>(gep->getOperand(0));
	assert(global && "assertion");
	ConstantDataArray* array =
		dyn_cast<ConstantDataArray>(global->getInitializer());
	if (array->isCString())
		output = array->getAsCString();
}

/*
 * Helper Functions
 */
std::string
InfoAppPass::getKindId(std::string name, uint64_t *unique_id)
{
	std::stringstream SS;
	SS << (*unique_id)++;
	return name + SS.str();
}


/* 
 * ===  FUNCTION  =============================================================
 *         Name:  getMode
 *    Arguments:  -
 *  Description:  Read the mode from the file @MODE_FILE.
 * ============================================================================
 */
void
InfoAppPass::getMode() {
	std::ifstream ifmode;
	std::string tmp;
	ifmode.open(MODE_FILE);
	if (!ifmode.is_open()) {
		dbg_err("Failed to open mode file");
		exit(1);
	}
	ifmode >> tmp;
	mode = (unsigned char) atoi(tmp.c_str());
	ifmode >> tmp;
	if (ifmode.good()) {
		dbg_err("Mode File contains more than 1 number");
		exit(1);
	}
	if (mode < 1 || mode > MODE_MAX_NUM) {
		dbg_err("Wrong mode number");
		exit(1);
	}
}

}  //namespace deps

namespace  {
/* ID for InfoAppPass */
char InfoAppPass::ID = 0;

static RegisterPass<InfoAppPass>
	XX ("infoapp", "implements infoapp", true, true);


static void initializeInfoAppPasses(PassRegistry &Registry) {
	llvm::initializeAllocIdentifyPass(Registry);
	llvm::initializePDTCachePass(Registry);
}

static void registerInfoAppPasses(const PassManagerBuilder &,
								  PassManagerBase &PM)
{
	PM.add(llvm::createPromoteMemoryToRegisterPass());
	PM.add(llvm::createPDTCachePass());
	PM.add(new InfoAppPass());
}

class StaticInitializer {
	public:
		StaticInitializer() {
			char* passend = getenv("__PASSEND__");

			if (passend) {
				dbg_err("== EP_LoopOptimizerEnd ==");
				RegisterStandardPasses
				RegisterInfoAppPass(PassManagerBuilder::EP_LoopOptimizerEnd,
							registerInfoAppPasses);
			} else {
				dbg_err("== EP_ModuleOptimizerEarly ==");
				RegisterStandardPasses
				RegisterInfoAppPass(PassManagerBuilder::EP_ModuleOptimizerEarly,
							registerInfoAppPasses);
			}

			PassRegistry &Registry = *PassRegistry::getPassRegistry();
			initializeInfoAppPasses(Registry);
		}
};

static StaticInitializer InitializeEverything;


void
dbg_err(std::string s)
{
	llvm::errs() << "[InfoApp] DBG:" << s << "\n";
}

void
dbg_msg(std::string a, std::string b)
{
	llvm::errs() << "[InfoApp] DBG:" << a << b << "\n";
}

} /* end of namespace */


static void
getWhiteList() {
	std::string line, file, function, conv;
	std::string overflow, shift;
	bool conv_bool, overflow_bool, shift_bool;
	unsigned numLines;
	unsigned i;
	unsigned pos = 0;
	std::ifstream whitelistFile;
	whitelistFile.open(WHITE_LIST);
	//get number of lines
	numLines = 0;
	while (whitelistFile.good()) {
		std::getline(whitelistFile, line);
		if (!line.empty())
			numLines++;
	}

	whitelistFile.clear();
	whitelistFile.seekg(0, std::ios::beg);

	rmCheckList = new rmChecks[numLines];
	for (i = 0; i < numLines; i++) {
		getline(whitelistFile, line);
		//handle each line
		pos = 0;
		function = line.substr(pos, line.find(","));
		pos = line.find(",") + 1;
		file = line.substr(pos, line.find(",", pos) - pos);
		pos = line.find(",", pos) + 1;
		conv = line.substr(pos, line.find(",", pos) - pos);
		pos = line.find(",", pos) + 1;
		overflow = line.substr(pos, line.find(",", pos) - pos);
		pos = line.find(",", pos) + 1;
		shift = line.substr(pos, line.size() - pos);

		if (conv.compare("true") == 0)
			conv_bool = true;
		else
			conv_bool = false;

		if (overflow.compare("true") == 0)
			overflow_bool = true;
		else
			overflow_bool = false;

		if (shift.compare("true") == 0)
			shift_bool = true;
		else
			shift_bool = false;

		if (function.compare("0") == 0)
			rmCheckList[i].func = (char*) 0;
		else {
			rmCheckList[i].func = new char[strlen(function.c_str())+1];
			for (unsigned j = 0; j < strlen(function.c_str()); j++)
				rmCheckList[i].func[j] = function[j];
			rmCheckList[i].func[strlen(function.c_str())] = '\0';
		}
		if (file.compare("0") == 0)
			rmCheckList[i].fname =  (char *) 0;
		else {
			rmCheckList[i].fname = new char[strlen(file.c_str()) +1];
			for (unsigned j = 0; j < strlen(file.c_str()); j++)
				rmCheckList[i].fname[j] = file[j];
			rmCheckList[i].fname[strlen(file.c_str())] = '\0';

		}
		rmCheckList[i].conversion = conv_bool;
		rmCheckList[i].overflow = overflow_bool;
		rmCheckList[i].shift = shift_bool;

	}
	whitelistFile.close();
}

void
InfoAppPass::setWrapper(CallInst *ci, Module &M, Function *func)
{
	FunctionType *ftype = func->getFunctionType();
	std::string fname = "__ioc_" + std::string(func->getName());

	Constant* ioc_wrapper = M.getOrInsertFunction(fname,
												  ftype,
												  func->getAttributes());
	ci->setCalledFunction(ioc_wrapper);

}

/*
 * Print Helpers
 */
void
InfoAppPass::format_ioc_report_func(const Value* val, raw_string_ostream& rs)
{
	const CallInst* ci = dyn_cast<CallInst>(val);
	assert(ci && "CallInst casting check");

	if (!xformMap[ci])
		return;

	const Function* func = ci->getCalledFunction();
	assert(func && "Function casting check");

	//line & column
	dbg_err(func->getName());
	uint64_t line = getIntFromVal(ci->getOperand(0));
	uint64_t col = getIntFromVal(ci->getOperand(1));

	//XXX: restructure
	std::string fname = "";
	getStringFromVal(ci->getOperand(2), fname);

	rs << func->getName().str() << ":";
	rs << fname << ":" ;
	rs << " (line ";
	rs << line;
	rs << ", col ";
	rs << col << ")";

	//ioc_report_* specific items
	if (ioc_report_all_but_conv(func->getName()))
	{
		;
	} else if (func->getName() == "__ioc_report_conversion") {
		;
	} else {
		;
		//    assert(! "invalid function name");
	}
}


#if 0
#if 0
								//std::vector index_vector;
								//index_vector.push_back( ConstantSInt::get( ATy, 0 );
								std::vector<Value*>new_idx;
								new_idx.push_back(ConstantInt::get(M.getContext(), APInt(32, 0)));
								new_idx.push_back(ConstantInt::get(M.getContext(), APInt(32, arr_n)));

								Instruction *nextaddr = GetElementPtrInst::Create(tmpgl,
																				  new_idx.begin(),
																				  new_idx.end(),
																				  "",
																				  0);
#endif

				 	PointerType* arrayPtr = PointerType::get(IntegerType::get(M.getContext(), 32), 0);
 
					std::vector<Type*>FuncTy_args;
					FuncTy_args.push_back(arrayPtr);
					FuncTy_args.push_back(IntegerType::get(M.getContext(), 32));
					FunctionType* FuncTy = FunctionType::get(
									/*Result=*/IntegerType::get(M.getContext(), 32),
									/*Params=*/FuncTy_args,
									/*isVarArg=*/false);


					Function* func_foo = M.getFunction("foo");
					if (!func_foo) {
						func_foo = Function::Create(
										/*Type=*/FuncTy,
										/*Linkage=*/GlobalValue::ExternalLinkage,
										/*Name=*/"foo", &M); 
						func_foo->setCallingConv(CallingConv::C);
					}

#if 0
 Function::arg_iterator args = func_foo->arg_begin();
 Value* ptr_s = args++;
 ptr_s->setName("s");
 Value* int32_c = args++;
 int32_c->setName("c");
 
 BasicBlock* label_entry = BasicBlock::Create(M.getContext(), "entry",func_foo,0);
 
#endif
 BasicBlock *label_entry = bb;
 // Block entry (label_entry)
 CastInst* int64_idxprom = new SExtInst(int32_c, IntegerType::get(M.getContext(), 64), "idxprom", label_entry);
 std::vector<Value*> ptr_arrayidx_indices;
 
 ConstantInt* const_int64_6 = ConstantInt::get(M.getContext(), APInt(64, StringRef("0"), 10));
 ptr_arrayidx_indices.push_back(const_int64_6);
 ptr_arrayidx_indices.push_back(int64_idxprom);

 GetElementPtrInst* ptr_arrayidx = GetElementPtrInst::Create(tmpgl, ptr_arrayidx_indices, "arrayidx", label_entry);
 //LoadInst* int32_5 = new LoadInst(ptr_arrayidx, "", false, label_entry);
 //int32_5->setAlignment(4);
 //ReturnInst::Create(M.getContext(), int32_5, label_entry);

								Function *f;
								Instruction *injIns;

								//argument just needed for string
								Constant *fc = M.getOrInsertFunction("checkIoc", //name
																	 Type::getInt32Ty(M.getContext()), //function type
																	 arrayPtr,
																	 Type::getInt32Ty(M.getContext()),//position variable
																	 /*Linkage=*/GlobalValue::ExternalLinkage,
																	 (Type *)0);
								std::vector<Value *> fargs;
								fargs.push_back(ptr_arrayidx);       
								fargs.push_back(ConstantInt::get(M.getContext(), APInt(32, ioc_cnt)));       

								f = cast<Function>(fc);
								ArrayRef<Value *> functionArguments(fargs);
								injIns = CallInst::Create(f, functionArguments, "");
								ci->getParent()->getInstList().insert(ci, injIns);
							}
					}
				} 
			}
		}
	}
}
#endif

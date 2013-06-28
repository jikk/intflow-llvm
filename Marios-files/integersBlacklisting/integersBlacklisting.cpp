/*
 * ===================================================================================
 *
 *       Filename:  integersBlacklisting.cpp
 *
 *    Description:  A pass that handles calls to
 *                  blacklisted functions.
 *
 *        Version:  1.0
 *        Created:  06/10/2013 06:00:35 PM
 *       Revision:  none
 *       Compiler:  llvm
 *
 *         Author:  Marios Pomonis
 *   Organization:  Columbia University
 *
 * ===================================================================================
 */

#include <fstream>
#include <string>
#include <set>
#include <vector>
#include <string>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/ADT/Hashing.h"

#define LLDIV   "lldiv"
using namespace llvm;


/* 
 * ===  FUNCTION  ====================================================================
 *         Name:  fillBlacklistedFunctions
 *  Description:  fills the @blacklistedfunctions set with the names of the
 *                blacklisted functions.
 * ===================================================================================
 */
void
fillBlacklistedFunctions (std::set<std::string> &blacklistedFunctions)
{
        blacklistedFunctions.insert(LLDIV);
        /* add more blacklisted function names here */
}
/* -----  end of function fillBlacklistedFunctions  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  blacklisted
 *  Description:  Returns true if the function called of @call is blacklisted
 *                (that is exists in @blacklistedFunctions)
 * =====================================================================================
 */
bool
blacklisted (CallInst *call, std::set<std::string> &blacklistedFunctions)
{
        if (blacklistedFunctions.find(call->getCalledFunction()->getName().str()) !=
                                blacklistedFunctions.end())
                return true;
        else
                return false;

}
/* -----  end of function blacklisted  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  lldivHandling
 *  Description:  Adds a call to lldivWarning function defined in another file
 *                (temporary file name warnings.c). Warnings.c should be linked
 *                with the input file.
 * =====================================================================================
 */
void
lldivHandling (CallInst *call, Module &M)
{
        Constant *c = M.getOrInsertFunction("lldivWarning",
                        Type::getVoidTy(M.getContext()),
                        Type::getInt64Ty(M.getContext()),
                        (Type *)0 );
        Function *f = cast<Function>(c);
        std::vector<Value *> args;
        args.push_back(call->getArgOperand(1));
        ArrayRef<Value *> arrayArgs(args);
        Instruction *newInst = CallInst::Create(f, arrayArgs, "");
        call->getParent()->getInstList().insert(call, newInst);
}
/* -----  end of function lldivHandling  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  handleBlacklistedFunction
 *  Description:  adds handling before @call
 * =====================================================================================
 */
void
handleBlacklistedFunction (CallInst *call, Module &M)
{
        if (strncmp(call->getCalledFunction()->getName().str().c_str(), LLDIV, 5) == 0)
                /* handle LLDIV */
                lldivHandling(call, M);
        else
                /* do nothing */
                ;
}
/* -----  end of function handleBlacklistedFunction  ----- */

namespace {
        struct BlackListing : public ModulePass {
                static char ID;
                BlackListing() : ModulePass(ID) {}

                virtual bool runOnModule(Module &M) {
                        CallInst *call;
                        BasicBlock * bb;
                        Module::iterator funcIt;
                        Function::iterator bbIt;
                        BasicBlock::iterator instIt;
                        Instruction *instruction;
                        std::set<std::string> blacklistedFunctions;
                        /* a set that holds
                           blacklisted function
                           names*/
                        /* fill set with functionNames */
                        fillBlacklistedFunctions(blacklistedFunctions);

                        for (funcIt = M.begin(); funcIt != M.end();
                                        funcIt++) {
                                /* Source code function handling */
                                for (bbIt = funcIt->begin(); bbIt != funcIt->end();
                                                bbIt++) {
                                        for (instIt = bbIt->begin();
                                                        instIt != bbIt->end();
                                                        instIt++) {
                                                instruction = instIt;
                                                if (isa<CallInst>(instruction)) {
                                                        call = dyn_cast<CallInst>(
                                                                        instruction);
                                                        if (blacklisted(call,
                                                                blacklistedFunctions)) 
                                                                /* handle blacklistedFunction */
                                                                handleBlacklistedFunction(call, M);
                                                        }
                                                }
                                        }
                                }
                        }
                        return true;
                }
        };
}

char BlackListing::ID = 0;
static RegisterPass<BlackListing> Y("integersBlacklisting", "Adds checks to blacklisted function calls",
                false /* Only looks at CFG */,
                false /* Analysis Pass */);

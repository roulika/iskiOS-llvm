//===--------------------- X86KernelShadowStack.cpp ----------------------===//
//===-------------- X86_64 Kernel Shadow Call Stack Pass -----------------===//
//===---------------------- Part of Research Project ---------------------===//
//=== IskiOS: Lightweight Defense Against Kernel-Level Code-Reuse Attacks ===//
//===---------------------------------------------------------------------===//
//
// This file was written by Mohammad Hedayati & Spyridoula Gravani at the
// University of Rochester.
// All Right Reserved.
//
//===---------------------------------------------------------------------===//
// The X86KernelShadowStack pass instruments function prologs/epilogs to check
// that the return address has not been corrupted during the execution of the
// function. The return address is stored in a 'shadow call stack' addressed
// by flipping the 15th bit of the current %rsp.
//===---------------------------------------------------------------------===//

#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

class X86KernelShadowStack : public MachineFunctionPass {
public:
  static char ID;

  X86KernelShadowStack() : MachineFunctionPass(ID) {
    initializeX86KernelShadowStackPass(*PassRegistry::getPassRegistry());
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction &Fn) override;

private:
};

char X86KernelShadowStack::ID = 0;

} // end anonymous namespace.

bool X86KernelShadowStack::runOnMachineFunction(MachineFunction &Fn) {
  return false;
}

INITIALIZE_PASS(X86KernelShadowStack, "kernel-shadow-stack",
                "Kernel Shadow Stack", false, false)

FunctionPass *llvm::createX86KernelShadowStackPass() {
  return new X86KernelShadowStack();
}

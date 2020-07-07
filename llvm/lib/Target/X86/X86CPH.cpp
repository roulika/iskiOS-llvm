//===---------------------------- X86CPH.cpp -----------------------------===//
//===----------------- X86_64 Code Pointer Hiding Pass -------------------===//
//===---------------------- Part of Research Project ---------------------===//
//=== IskiOS: Lightweight Defense Against Kernel-Level Code-Reuse Attacks ===//
//===---------------------------------------------------------------------===//
//
// This file was written by Mohammad Hedayati & Spyridoula Gravani at the
// University of Rochester.
// All Right Reserved.
//
//===---------------------------------------------------------------------===//
// The X86CPH pass implements a simple approach to code-pointer hiding where
// every function entry and every callsite is padded with a random number
// of trap instructions. In particular, in every function entry we add a jump
// instruction to the actual first instruction of the function and a random
// number of trap instructions after the jump. Similarly, we prepend each
// callsite with a jump to the call and a random number of traps, and we
// append it with a jump to the rest of the code and a random number of traps
// after the jump.
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
#include "llvm/Support/Process.h"
#include "llvm/Support/raw_ostream.h"

#define SCALE_FACTOR 100

using namespace llvm;
using namespace sys;

namespace {

class X86CPH : public MachineFunctionPass {
public:
  static char ID;

  X86CPH() : MachineFunctionPass(ID) {
    initializeX86CPHPass(*PassRegistry::getPassRegistry());
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction &Fn) override;

private:
};

char X86CPH::ID = 0;

} // end anonymous namespace.

bool X86CPH::runOnMachineFunction(MachineFunction &Fn) {
  //return false;
  /* Parts of kernel boot loader (i.e., /arch/x86/boot/compressed/*) */
  if (Fn.getFunction().hasFnAttribute(Attribute::Naked) ||
      (Fn.getTarget().getCodeModel() != CodeModel::Kernel))
    return false;

  if (Fn.empty())
    return false;

  if (!Fn.getSubtarget<X86Subtarget>().is64Bit())
    return false;

  if (Fn.getName() == "sync_regs" || Fn.getName() == "prepare_exit_to_usermode")
    return false;

  MachineBasicBlock &MBB = Fn.front();
  const MachineBasicBlock *NonEmpty = MBB.empty() ? MBB.getFallThrough() : &MBB;
  const DebugLoc &DL = NonEmpty->front().getDebugLoc();
  const TargetInstrInfo *TII = Fn.getSubtarget().getInstrInfo();

  {
    auto MBBI = MBB.begin();
    unsigned count = Process::GetRandomNumber() % SCALE_FACTOR;
    MCSymbol *JmpSymbol = Fn.getContext().createTempSymbol();

    // jmp JmpSymbol
    BuildMI(MBB, MBBI, DL, TII->get(X86::JMP_1)).addSym(JmpSymbol);

    for (unsigned i = 0; i < count; ++i) {
      // ud2
      BuildMI(MBB, MBBI, DL, TII->get(X86::TRAP));
    }

    auto last = BuildMI(MBB, MBBI, DL, TII->get(X86::TRAP));
    last->setPostInstrSymbol(Fn, JmpSymbol);
  }

  for (auto &MBB : Fn) {
    if (MBB.empty())
      continue;

    for (auto &MI : MBB) {
      if (MI.isCall()) {
        if (MI.isReturn())
          continue;

        // before call
        {
          unsigned count = Process::GetRandomNumber() % SCALE_FACTOR;
          MCSymbol *JmpSymbol = Fn.getContext().createTempSymbol();

          // jmp JmpSymbol
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::JMP_1))
              .addSym(JmpSymbol);

          for (unsigned i = 0; i < count; ++i) {
            // ud2
            BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::TRAP));
          }

          auto last = BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::TRAP));
          last->setPostInstrSymbol(Fn, JmpSymbol);
        }

        // after call
        {
          unsigned count = Process::GetRandomNumber() % SCALE_FACTOR;
          MCSymbol *JmpSymbol = Fn.getContext().createTempSymbol();

          auto last = BuildMI(MBB, std::next(MI.getIterator()),
                              MI.getDebugLoc(), TII->get(X86::TRAP));
          last->setPostInstrSymbol(Fn, JmpSymbol);

          for (unsigned i = 0; i < count; ++i) {
            // ud2
            BuildMI(MBB, std::next(MI.getIterator()), MI.getDebugLoc(),
                    TII->get(X86::TRAP));
          }

          // jmp JmpSymbol
          BuildMI(MBB, std::next(MI.getIterator()), MI.getDebugLoc(),
                  TII->get(X86::JMP_1))
              .addSym(JmpSymbol);
        }
      }
    }
  }

  return true;
}

INITIALIZE_PASS(X86CPH, "kernel-code-pointer-hiding",
                "Kernel Code Pointer Hiding", false, false)

FunctionPass *llvm::createX86CPHPass() { return new X86CPH(); }

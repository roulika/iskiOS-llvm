//===---------------------------- X86SMEP.cpp ----------------------------===//
//===--------- X86_64 Supervisor Mode Execution Prevention Pass ----------===//
//===---------------------- Part of Research Project ---------------------===//
//=== IskiOS: Lightweight Defense Against Kernel-Level Code-Reuse Attacks ===//
//===---------------------------------------------------------------------===//
//
// This file was written by Spyridoula Gravani at the University of Rochester.
// All Right Reserved.
//
//===---------------------------------------------------------------------===//
// The X86SMEP pass instruments indirect branches and return instructions
// with code that verifies control will not flow to user space memory.
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

using namespace llvm;
using namespace sys;

namespace {

class X86SMEP : public MachineFunctionPass {
 public:
  static char ID;

  X86SMEP() : MachineFunctionPass(ID) {
    initializeX86SMEPPass(*PassRegistry::getPassRegistry());
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction &Fn) override;

 private:
};

char X86SMEP::ID = 0;

}  // end anonymous namespace.

bool X86SMEP::runOnMachineFunction(MachineFunction &Fn) {
  //return false;
  /* Parts of kernel boot loader (i.e., /arch/x86/boot/compressed/*) */
  if (Fn.getFunction().hasFnAttribute(Attribute::Naked) ||
      (Fn.getTarget().getCodeModel() != CodeModel::Kernel))
    return false;

  if (Fn.empty()) return false;

  if (!Fn.getSubtarget<X86Subtarget>().is64Bit()) return false;

  if (Fn.getName() == "sync_regs" || Fn.getName() == "prepare_exit_to_usermode")
    return false;

  const TargetInstrInfo *TII = Fn.getSubtarget().getInstrInfo();

  for (auto &MBB : Fn) {
    if (MBB.empty()) continue;

    for (auto &MI : MBB) {
      // If MI is a return, handle it first.
      if (MI.isReturn() && !MI.isCall()) {
        if (Fn.getName() != "copy_user_handle_tail" &&
            Fn.getName() != "__startup_64" &&
            Fn.getName() != "prepare_exit_to_usermode") {
          // mov r11, [rsp]
          addDirectMem(
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64rm))
                  .addDef(X86::R11),
              X86::RSP);
          // add rsp, 0x8
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::ADD64ri8), X86::RSP)
              .addReg(X86::RSP)
              .addImm(0x8);

          // jmp *r11
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::JMP64r))
              .addReg(X86::R11);

          MI.eraseFromParent();
          break;
        }
      }

      // Must either be a call or a branch.
      if (!MI.isCall() && !MI.isBranch()) continue;

      // If the first operand isn't a register, this is a branch or call
      // instruction with an immediate operand which doesn't need to be
      // hardened.
      if (!MI.getOperand(0).isReg()) continue;

      if (MI.getOperand(0).getReg() == X86::NoRegister) continue;

      if (MI.getOperand(0).getReg() == X86::RIP ||
          MI.getOperand(0).getReg() == X86::EIP)
        continue;

      // errs() << "===================== " << MI << "\n";

      MCSymbol *SkipSymbol = Fn.getContext().createTempSymbol();

      // For all of these, the target register is the first operand of the
      // instruction.
      auto &TargetOp = MI.getOperand(0);

      // bt $63, %TargetOp
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::BT64ri8))
          .addReg(TargetOp.getReg())
          .addImm(63);

      // jb SkipSymbol
      BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::JCC_1))
          .addSym(SkipSymbol)
          .addImm(X86::COND_B);

      // // ud2
      // auto trapInst = BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::TRAP));

      // nop
      auto trapInst = BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::NOOP));

      trapInst->setPostInstrSymbol(Fn, SkipSymbol);
    }
  }
  return true;
}

INITIALIZE_PASS(X86SMEP, "smep", "Kernel Instrumentation Emulating SMEP", false,
                false)

FunctionPass *llvm::createX86SMEPPass() { return new X86SMEP(); }

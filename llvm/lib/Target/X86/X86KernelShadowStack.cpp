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

#define PGSIZE 4096

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

}  // end anonymous namespace.

bool X86KernelShadowStack::runOnMachineFunction(MachineFunction &Fn) {
  /* Parts of kernel boot loader (i.e., /arch/x86/boot/compressed/*) */
  if ((Fn.getTarget().getCodeModel() != CodeModel::Kernel)) {
    errs() << "CodeModel is not Kernel "
           << Fn.getMMI().getModule()->getSourceFileName() << "\n";
    return false;
  }

  if (Fn.getFunction().hasFnAttribute(Attribute::Naked)) return false;

  if (Fn.empty()) return false;

  if (!Fn.getRegInfo().tracksLiveness()) {
    errs() << "function doesn't track liveness, skipping...\n";
    return false;
  }

  if (!Fn.getSubtarget<X86Subtarget>().is64Bit()) return false;

  if (Fn.getName() == "sync_regs" ||
      Fn.getName() == "prepare_exit_to_usermode" ||
      Fn.getName() == "__startup_secondary_64")
    return false;

  bool HasReturn = false;
  for (auto &MBB : Fn) {
    if (MBB.empty()) continue;

    const MachineInstr &MI = MBB.instr_back();
    if (MI.isReturn()) HasReturn = true;
  }

  if (!HasReturn) return false;

  MachineBasicBlock &MBB = Fn.front();
  const MachineBasicBlock *NonEmpty = MBB.empty() ? MBB.getFallThrough() : &MBB;
  const DebugLoc &DL = NonEmpty->front().getDebugLoc();
  const TargetInstrInfo *TII = Fn.getSubtarget().getInstrInfo();

  auto MBBI = MBB.begin();

  /* Prolog Instrumentation */

  // push rcx
  BuildMI(MBB, MBBI, DL, TII->get(X86::PUSH64r))
      .addReg(X86::RCX, RegState::Kill);

  // push rdx
  BuildMI(MBB, MBBI, DL, TII->get(X86::PUSH64r))
      .addReg(X86::RDX, RegState::Kill);

  // xor rcx, rcx
  BuildMI(MBB, MBBI, DL, TII->get(X86::XOR64rr))
      .addDef(X86::RCX)
      .addReg(X86::RCX, RegState::Undef)
      .addReg(X86::RCX, RegState::Undef);

  // rdpkru
  BuildMI(MBB, MBBI, DL, TII->get(X86::RDPKRUr));

  // wrpkru
  BuildMI(MBB, MBBI, DL, TII->get(X86::WRPKRUr));

  // mov r10, [rsp+0x10]
  addRegOffset(BuildMI(MBB, MBBI, DL, TII->get(X86::MOV64rm)).addDef(X86::R10),
               X86::RSP, false, 0x10);

  // mov [rsp+0x10-4*PGSIZE], r10
  addRegOffset(BuildMI(MBB, MBBI, DL, TII->get(X86::MOV64mr)), X86::RSP, false,
               0x10 - 4 * PGSIZE)
      .addDef(X86::R10);

  // wrpkru
  BuildMI(MBB, MBBI, DL, TII->get(X86::WRPKRUr));

  // pop rdx
  BuildMI(MBB, MBBI, DL, TII->get(X86::POP64r))
      .addReg(X86::RDX, RegState::Kill);

  // pop rcx
  BuildMI(MBB, MBBI, DL, TII->get(X86::POP64r))
      .addReg(X86::RCX, RegState::Kill);

  /* Epilog Instrumentation */

  for (auto &MBB : Fn) {
    if (MBB.empty()) continue;

    MachineInstr &MI = MBB.instr_back();
    if (MI.isReturn()) {
      // mov r10, [rsp-4*PGSIZE]
      addRegOffset(BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64rm))
                       .addDef(X86::R10),
                   X86::RSP, false, -4 * PGSIZE);

      // mov [rsp], r10
      addDirectMem(BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64mr)),
                   X86::RSP)
          .addReg(X86::R10);
    }
  }
  return true;
}

INITIALIZE_PASS(X86KernelShadowStack, "kernel-shadow-stack",
                "Kernel Shadow Stack", false, false)

FunctionPass *llvm::createX86KernelShadowStackPass() {
  return new X86KernelShadowStack();
}

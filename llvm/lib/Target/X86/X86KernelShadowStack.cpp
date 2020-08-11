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
// The X86KernelShadowStack pass implements a race-free shadow stack for the
// Linux kernel on x86_64. In particular, it instruments function prologs with
// code that enables access to a write-protected shadow call stack, stores the
// address on top of the shadow stack and disables write access using the
// wrpkru instruction.
//
// The pass also instruments every function epilog with code that moves the
// return address from the shadow stack to %r10 and then jumps to that
// address. Replacing the return instruction with a jump prevents race hazards
// inherent to the x86_64 ret implementation (pop+jmp microarchitecturally).
//
// Finally, the pass instruments callsites with code that passes the return
// address to the callee via %r10 in order to prevent race hazards inherent to
// the x86_64 "call" implementation (push+jmp microarchitecturally).

// Note: the shadow call stack is addressed 0x4000 relative current %rsp since
// we've increased each stack in the kernel by 4KB pages.
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

#define SAFE_WRPKRU

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

  if (Fn.getName() == "sync_regs")
    return false;

  MachineBasicBlock &MBB = Fn.front();
  const MachineBasicBlock *NonEmpty = MBB.empty() ? MBB.getFallThrough() : &MBB;
  const DebugLoc &DL = NonEmpty->front().getDebugLoc();
  const TargetInstrInfo *TII = Fn.getSubtarget().getInstrInfo();

  if (Fn.getName() != "copy_user_handle_tail" &&
      Fn.getName() != "__startup_64" &&
      Fn.getName() != "prepare_exit_to_usermode" &&
      Fn.getName() != "__startup_secondary_64") {
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

    // xor %rax, $(1 << 20)
    BuildMI(MBB, MBBI, DL, TII->get(X86::XOR64ri32), X86::RAX)
        .addReg(X86::RAX)
        .addImm(1 << 20);

    // wrpkru
    BuildMI(MBB, MBBI, DL, TII->get(X86::WRPKRUr));

#ifdef SAFE_WRPKRU
{
    MCSymbol *SkipSymbol = Fn.getContext().createTempSymbol();

    // mov %rcx, %cs
    BuildMI(MBB, MBBI, DL, TII->get(X86::MOV64rs), X86::RCX).addReg(X86::CS);

    // testb $3, %cl
    BuildMI(MBB, MBBI, DL, TII->get(X86::TEST8ri)).addReg(X86::CL).addImm(3);

    // je SkipSymbol
    BuildMI(MBB, MBBI, DL, TII->get(X86::JCC_1))
        .addSym(SkipSymbol)
        .addImm(X86::COND_E);

    // ud2
    auto trapInst = BuildMI(MBB, MBBI, DL, TII->get(X86::TRAP));

    trapInst->setPostInstrSymbol(Fn, SkipSymbol);

    // xor rcx, rcx
    BuildMI(MBB, MBBI, DL, TII->get(X86::XOR64rr))
        .addDef(X86::RCX)
        .addReg(X86::RCX, RegState::Undef)
        .addReg(X86::RCX, RegState::Undef);
}
#endif

    // mov [rsp+0x10-4*PGSIZE], r10
    addRegOffset(BuildMI(MBB, MBBI, DL, TII->get(X86::MOV64mr)), X86::RSP,
                 false, 0x10 - 4 * PGSIZE)
        .addDef(X86::R10);

    // xor %rax, $(1 << 20)
    BuildMI(MBB, MBBI, DL, TII->get(X86::XOR64ri32), X86::RAX)
        .addReg(X86::RAX)
        .addImm(1 << 20);

    // wrpkru
    BuildMI(MBB, MBBI, DL, TII->get(X86::WRPKRUr));

#ifdef SAFE_WRPKRU
{
    MCSymbol *SkipSymbol = Fn.getContext().createTempSymbol();

    // mov %rcx, %cs
    BuildMI(MBB, MBBI, DL, TII->get(X86::MOV64rs), X86::RCX).addReg(X86::CS);

    // testb $3, %cl
    BuildMI(MBB, MBBI, DL, TII->get(X86::TEST8ri)).addReg(X86::CL).addImm(3);

    // je SkipSymbol
    BuildMI(MBB, MBBI, DL, TII->get(X86::JCC_1))
        .addSym(SkipSymbol)
        .addImm(X86::COND_E);

    // ud2
    auto trapInst = BuildMI(MBB, MBBI, DL, TII->get(X86::TRAP));

    trapInst->setPostInstrSymbol(Fn, SkipSymbol);
}
#endif

    // pop rdx
    BuildMI(MBB, MBBI, DL, TII->get(X86::POP64r))
        .addReg(X86::RDX, RegState::Kill);

    // pop rcx
    BuildMI(MBB, MBBI, DL, TII->get(X86::POP64r))
        .addReg(X86::RCX, RegState::Kill);

#if 0
  /* NOTE: Uncomment the following two instructions to identify
   * uninstrumented functions -- part of *.S files that LLVM does
   * not go over. It will cause infinite-loop which you can use GDB
   * to find the culprit callsite and address the issue. Good Luck!
   */
  {
    auto MBBI = MBB.begin();
    // r10 == [rsp]? If not, spin till we find you!

    MCSymbol *LoopSymbol = Fn.getContext().createTempSymbol();

    // cmp r10, [rsp]
    auto cmpInst = addDirectMem(
        BuildMI(MBB, MBBI, DL, TII->get(X86::CMP64rm)).addDef(X86::R10),
        X86::RSP);

    cmpInst->setPreInstrSymbol(Fn, LoopSymbol);

    // jne LoopSymbol
    BuildMI(MBB, MBBI, DL, TII->get(X86::JCC_1))
        .addSym(LoopSymbol)
        .addImm(X86::COND_NE);
  }
#endif
  }

  /* Epilog Instrumentation */

  for (auto &MBB : Fn) {
    if (MBB.empty()) continue;

    MachineInstr &MI = MBB.instr_back();
    if (MI.isReturn()) {
      if (MI.isCall()) continue;

      if (Fn.getName() != "copy_user_handle_tail" &&
          Fn.getName() != "__startup_64" &&
          Fn.getName() != "prepare_exit_to_usermode" &&
          Fn.getName() != "__startup_secondary_64") {
        /* Use jmp to avoid race. */

        // mov r10, [rsp-4*PGSIZE]
        addRegOffset(BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64rm))
                         .addDef(X86::R10),
                     X86::RSP, false, -4 * PGSIZE);

        // add rsp, 0x8
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::ADD64ri8), X86::RSP)
            .addReg(X86::RSP)
            .addImm(0x8);

        // jmp *r10
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::JMP64r))
            .addReg(X86::R10);

        MI.eraseFromParent();
      }
    }
  }

  /* Callsite Instrumentation */

  for (auto &MBB : Fn) {
    if (MBB.empty()) continue;
    for (auto &MI : MBB) {
      if (MI.isCall()) {
#if 1
        if (MI.isReturn()) {
          // mov r10, [rsp-4*PGSIZE]
          addRegOffset(
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64rm))
                  .addDef(X86::R10),
              X86::RSP, false, -4 * PGSIZE);

          continue;
        }

        MCSymbol *RetSymbol = Fn.getContext().createTempSymbol();
        MI.setPostInstrSymbol(Fn, RetSymbol);

        /* Note: If the call is already using R10 as a pointer, we change it
         * to use R11 instead.
         */
        if (MI.findRegisterUseOperand(X86::R10) ||
            MI.hasRegisterImplicitUseOperand(X86::R10)) {
          // mov r11, r10
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64rr), X86::R11)
              .addReg(X86::R10);

          // lea r10, RetSymbol
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::LEA64r), X86::R10)
              .addReg(/*Base*/ X86::RIP)
              .addImm(/*Scale*/ 1)
              .addReg(/*Index*/ 0)
              .addSym(RetSymbol)
              .addReg(/*Segment*/ 0);

          MI.getOperand(0).setReg(X86::R11);
        } else {
          // lea r10, RetSymbol
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::LEA64r), X86::R10)
              .addReg(/*Base*/ X86::RIP)
              .addImm(/*Scale*/ 1)
              .addReg(/*Index*/ 0)
              .addSym(RetSymbol)
              .addReg(/*Segment*/ 0);
        }
#endif
        // callq
      }
    }
  }
  return true;
}

INITIALIZE_PASS(X86KernelShadowStack, "kernel-shadow-stack",
                "Kernel Shadow Stack", false, false)

FunctionPass *llvm::createX86KernelShadowStackPass() {
  return new X86KernelShadowStack();
}

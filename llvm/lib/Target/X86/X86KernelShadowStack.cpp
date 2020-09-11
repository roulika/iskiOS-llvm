//===--------------------- X86KernelShadowStack.cpp ----------------------===//
//===-------------- X86_64 Kernel Shadow Call Stack Pass -----------------===//
//===---------------------- Part of Research Project ---------------------===//
//=== IskiOS: Lightweight Defense Against Kernel-Level Code-Reuse Attacks ===//
//===---------------------------------------------------------------------===//
//
// This file was written by Mohammad Hedayati & Spyridoula Gravani at the
// University of Rochester.
// All Rights Reserved.
//
//===---------------------------------------------------------------------===//
// The X86KernelShadowStack pass implements a write-protected race-free shadow
// stack for the Linux kernel on x86_64 using Intel's PKU feature.
//
// The main idea is to instrument each callsite with code that enables access
// to a write-protected shadow call stack, stores the return address
// address on top of the shadow stack, and disables write access using the
// wrpkru instruction. In addition, every function epilog should be
// instrumented with code that uses the address on top of the shadow stack to
// return to its caller.
// Ideally, the later should be done by pointing %rsp to the top of the
// shadow stack and allowing the ret instruction use the incorruptible return
// address. Unfortunately, this solution is not viable for kernel setting.
// Hardware interrupts may take place when %rsp is pointing to the
// write-protected shadow stack, causing the kernel to crash when attempting
// to save the processor state on what kernel thinks is its stack before
// executing the interrupt handler.
//
// To tackle this challenge, IskiOS reserves the %r10 register for exclusive
// use, and changes the calling convention to store the return address of each
// function in %r10.
// To achieve that, the pass instruments each callsite with code that:
//    1. enables write-access to shadow stack,
//    2. spills %r10 to shadow stack,
//    3. write-protects the shadow stack, and
//    4. updates %r10 with the new return address.
// The pass also replaces every ret with a jmp *(%r10) instruction.
// Following each callsite, the pass adds an instruction that updates %r10 with
// the return value stored on top of the shadow stack.
//
// Delayed Write Optimization (DWO)
// To minimize the number of expensive wrpkru instructions, the pass postpones
// writing to the shadow stack until necessary. To implement this optimization,
// the pass adds code that compares %r10 with the value on top of the shadow
// stack before every executing the wrpkru instruction. If equal, it skips
// writing to the shadow stack and just updates %r10 with the new return
// address. If not, it stores both the current and the updated %r10 to the
// shadow stack, halving the #wrpkrus.
//
// Safe WRPKRU (SAFE_WRPKRU)
// When defined, every wrpkru is followed by code that ensures that the
// privilege level of the currently executing code is 3 (i.e., kernel mode).
//
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
#define DWO


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
  return false;
  /* Parts of kernel boot loader (i.e., /arch/x86/boot/compressed/*) */
  if ((Fn.getTarget().getCodeModel() != CodeModel::Kernel)) return false;

  if (Fn.getFunction().hasFnAttribute(Attribute::Naked)) return false;

  if (Fn.empty()) return false;

  if (!Fn.getRegInfo().tracksLiveness()) return false;

  if (!Fn.getSubtarget<X86Subtarget>().is64Bit()) return false;

  if (Fn.getName() == "sync_regs") return false;
  if (Fn.getName() == "__startup_secondary_64") return false;

  const TargetInstrInfo *TII = Fn.getSubtarget().getInstrInfo();

  /* Prolog Instrumentation */
#if 0
  if (Fn.getName() != "copy_user_handle_tail" &&
      Fn.getName() != "__startup_64" &&
      Fn.getName() != "prepare_exit_to_usermode" &&
      Fn.getName() != "__startup_secondary_64" &&
      Fn.getName() != "x86_64_start_kernel") {
    MachineBasicBlock &MBB = Fn.front();
    const MachineBasicBlock *NonEmpty =
        MBB.empty() ? MBB.getFallThrough() : &MBB;
    const DebugLoc &DL = NonEmpty->front().getDebugLoc();
    auto MBBI = MBB.begin();

    /* NOTE: Uncomment the following two instructions to identify
     * uninstrumented functions -- part of *.S files that LLVM does
     * not go over. It will cause infinite-loop which you can use GDB
     * to find the culprit callsite and address the issue. Good Luck!
     */
    {
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
  }
#endif

  /* Epilog Instrumentation */
  if (Fn.getName() != "copy_user_handle_tail" &&
      Fn.getName() != "__startup_64" &&
      Fn.getName() != "prepare_exit_to_usermode" &&
      Fn.getName() != "__startup_secondary_64" &&
      Fn.getName() != "x86_64_start_kernel") {
    for (auto &MBB : Fn) {
      if (MBB.empty()) continue;
      MachineInstr &MI = MBB.instr_back();
      if (MI.isReturn()) {
        if (MI.isCall()) continue;

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

        MCSymbol *SkipSymbol = Fn.getContext().createTempSymbol();
#ifdef DWO
        // cmp [rsp-4*PGSIZE], r10
        addRegOffset(BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::CMP64mr)),
                     X86::RSP, false, -4 * PGSIZE)
            .addReg(X86::R10);

        // je SkipSymbol
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::JCC_1))
            .addSym(SkipSymbol)
            .addImm(X86::COND_E);
#endif

        // push rax
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::PUSH64r))
            .addReg(X86::RAX, RegState::Kill);

        // push rcx
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::PUSH64r))
            .addReg(X86::RCX, RegState::Kill);

        // push rdx
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::PUSH64r))
            .addReg(X86::RDX, RegState::Kill);

        MCSymbol *RetSymbol = Fn.getContext().createTempSymbol();
        MI.setPostInstrSymbol(Fn, RetSymbol);

        // xor rcx, rcx
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::XOR64rr))
            .addDef(X86::RCX)
            .addReg(X86::RCX, RegState::Undef)
            .addReg(X86::RCX, RegState::Undef);

        // rdpkru
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::RDPKRUr));

        // xor %rax, $(1 << 20)
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::XOR64ri32), X86::RAX)
            .addReg(X86::RAX)
            .addImm(1 << 20);

        // wrpkru
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::WRPKRUr));

#ifdef SAFE_WRPKRU
        {
          MCSymbol *SkipSymbol = Fn.getContext().createTempSymbol();

          // mov %rcx, %cs
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64rs), X86::RCX)
              .addReg(X86::CS);

          // testb $3, %cl
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::TEST8ri))
              .addReg(X86::CL)
              .addImm(3);

          // je SkipSymbol
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::JCC_1))
              .addSym(SkipSymbol)
              .addImm(X86::COND_E);

          // ud2
          auto trapInst =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::TRAP));

          trapInst->setPostInstrSymbol(Fn, SkipSymbol);

          // xor rcx, rcx
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::XOR64rr))
              .addDef(X86::RCX)
              .addReg(X86::RCX, RegState::Undef)
              .addReg(X86::RCX, RegState::Undef);
        }
#endif

        // mov [rsp+0x18-4*PGSIZE], r10
        addRegOffset(BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64mr)),
                     X86::RSP, false, 0x18 - 4 * PGSIZE)
            .addDef(X86::R10);

        // lea r10, RetSymbol
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::LEA64r), X86::R10)
            .addReg(/*Base*/ X86::RIP)
            .addImm(/*Scale*/ 1)
            .addReg(/*Index*/ 0)
            .addSym(RetSymbol)
            .addReg(/*Segment*/ 0);

        // mov [rsp+0x10-4*PGSIZE], r10
        addRegOffset(BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64mr)),
                     X86::RSP, false, 0x10 - 4 * PGSIZE)
            .addDef(X86::R10);

        // xor %rax, $(1 << 20)
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::XOR64ri32), X86::RAX)
            .addReg(X86::RAX)
            .addImm(1 << 20);

        // wrpkru
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::WRPKRUr));

#ifdef SAFE_WRPKRU
        {
          MCSymbol *SkipSymbol = Fn.getContext().createTempSymbol();

          // mov %rcx, %cs
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::MOV64rs), X86::RCX)
              .addReg(X86::CS);

          // testb $3, %cl
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::TEST8ri))
              .addReg(X86::CL)
              .addImm(3);

          // je SkipSymbol
          BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::JCC_1))
              .addSym(SkipSymbol)
              .addImm(X86::COND_E);

          // ud2
          auto trapInst =
              BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::TRAP));

          trapInst->setPostInstrSymbol(Fn, SkipSymbol);
        }
#endif

        // pop rdx
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::POP64r))
            .addReg(X86::RDX, RegState::Kill);

        // pop rcx
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::POP64r))
            .addReg(X86::RCX, RegState::Kill);

        // pop rax
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::POP64r))
            .addReg(X86::RAX, RegState::Kill);

        MCSymbol *JmpSymbol = Fn.getContext().createTempSymbol();

        // jmp SkipSymbol
        BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::JMP_1))
            .addSym(JmpSymbol);

        // lea r10, RetSymbol
        auto Inst =
            BuildMI(MBB, MI, MI.getDebugLoc(), TII->get(X86::LEA64r), X86::R10)
                .addReg(/*Base*/ X86::RIP)
                .addImm(/*Scale*/ 1)
                .addReg(/*Index*/ 0)
                .addSym(RetSymbol)
                .addReg(/*Segment*/ 0);

        // skip:
        Inst->setPreInstrSymbol(Fn, SkipSymbol);

        // jmp:
        Inst->setPostInstrSymbol(Fn, JmpSymbol);

#endif

        // callq

        // mov r10, [rsp-4*PGSIZE]
        addRegOffset(BuildMI(MBB, std::next(MI.getIterator()), MI.getDebugLoc(),
                             TII->get(X86::MOV64rm))
                         .addDef(X86::R10),
                     X86::RSP, false, -4 * PGSIZE);
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

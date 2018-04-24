#ifndef ARM_TARGET_SIGNAL_H
#define ARM_TARGET_SIGNAL_H

#include "cpu.h"

/* this struct defines a stack used during syscall handling */

typedef struct target_sigaltstack {
	abi_ulong ss_sp;
	abi_long ss_flags;
	abi_ulong ss_size;
} target_stack_t;


/*
 * sigaltstack controls
 */
#define TARGET_SS_ONSTACK	1
#define TARGET_SS_DISABLE	2

#define TARGET_MINSIGSTKSZ	2048
#define TARGET_SIGSTKSZ		8192

static inline abi_ulong get_sp_from_cpustate(CPUARMState *state)
{
   return state->regs[13];
}

void setup_frame(int usig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUARMState *regs);
void setup_rt_frame(int usig, struct target_sigaction *ka,
                    target_siginfo_t *info,
                    target_sigset_t *set, CPUARMState *env);
#endif /* ARM_TARGET_SIGNAL_H */

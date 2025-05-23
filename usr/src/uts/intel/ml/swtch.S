/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2024 MNX Cloud, Inc.
 */

/*
 * Process switching routines.
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/stack.h>
#include <sys/segments.h>
#include <sys/psw.h>

#include "assym.h"

/*
 * resume(thread_id_t t);
 *
 * a thread can only run on one processor at a time. there
 * exists a window on MPs where the current thread on one
 * processor is capable of being dispatched by another processor.
 * some overlap between outgoing and incoming threads can happen
 * when they are the same thread. in this case where the threads
 * are the same, resume() on one processor will spin on the incoming
 * thread until resume() on the other processor has finished with
 * the outgoing thread.
 *
 * The MMU context changes when the resuming thread resides in a different
 * process.  Kernel threads are known by resume to reside in process 0.
 * The MMU context, therefore, only changes when resuming a thread in
 * a process different from curproc.
 *
 * resume_from_intr() is called when the thread being resumed was not
 * passivated by resume (e.g. was interrupted).  This means that the
 * resume lock is already held and that a restore context is not needed.
 * Also, the MMU context is not changed on the resume in this case.
 *
 * resume_from_zombie() is the same as resume except the calling thread
 * is a zombie and must be put on the deathrow list after the CPU is
 * off the stack.
 */

#if LWP_PCB_FPU != 0
#error LWP_PCB_FPU MUST be defined as 0 for code in swtch.s to work
#endif	/* LWP_PCB_FPU != 0 */

/*
 * Save non-volatile regs other than %rsp (%rbx, %rbp, and %r12 - %r15)
 *
 * The stack frame must be created before the save of %rsp so that tracebacks
 * of swtch()ed-out processes show the process as having last called swtch().
 */
#define SAVE_REGS(thread_t, retaddr)			\
	movq	%rbp, T_RBP(thread_t);			\
	movq	%rbx, T_RBX(thread_t);			\
	movq	%r12, T_R12(thread_t);			\
	movq	%r13, T_R13(thread_t);			\
	movq	%r14, T_R14(thread_t);			\
	movq	%r15, T_R15(thread_t);			\
	pushq	%rbp;					\
	movq	%rsp, %rbp;				\
	movq	%rsp, T_SP(thread_t);			\
	movq	retaddr, T_PC(thread_t);		\
	movq	%rdi, %r12;				\
	call	__dtrace_probe___sched_off__cpu

/*
 * Restore non-volatile regs other than %rsp (%rbx, %rbp, and %r12 - %r15)
 *
 * We load up %rsp from the label_t as part of the context switch, so
 * we don't repeat that here.
 *
 * We don't do a 'leave,' because reloading %rsp/%rbp from the label_t
 * already has the effect of putting the stack back the way it was when
 * we came in.
 */
#define RESTORE_REGS(scratch_reg)			\
	movq	%gs:CPU_THREAD, scratch_reg;		\
	movq	T_RBP(scratch_reg), %rbp;		\
	movq	T_RBX(scratch_reg), %rbx;		\
	movq	T_R12(scratch_reg), %r12;		\
	movq	T_R13(scratch_reg), %r13;		\
	movq	T_R14(scratch_reg), %r14;		\
	movq	T_R15(scratch_reg), %r15

/*
 * Get pointer to a thread's hat structure
 */
#define GET_THREAD_HATP(hatp, thread_t, scratch_reg)	\
	movq	T_PROCP(thread_t), hatp;		\
	movq	P_AS(hatp), scratch_reg;		\
	movq	A_HAT(scratch_reg), hatp

#define	TSC_READ()					\
	call	tsc_read;				\
	movq	%rax, %r14;

/*
 * If we are resuming an interrupt thread, store a timestamp in the thread
 * structure.  If an interrupt occurs between tsc_read() and its subsequent
 * store, the timestamp will be stale by the time it is stored.  We can detect
 * this by doing a compare-and-swap on the thread's timestamp, since any
 * interrupt occurring in this window will put a new timestamp in the thread's
 * t_intr_start field.
 */
#define	STORE_INTR_START(thread_t)			\
	testw	$T_INTR_THREAD, T_FLAGS(thread_t);	\
	jz	1f;					\
0:							\
	TSC_READ();					\
	movq	T_INTR_START(thread_t), %rax;		\
	cmpxchgq %r14, T_INTR_START(thread_t);		\
	jnz	0b;					\
1:

	.global	kpti_enable

	ENTRY(resume)
	movq	%gs:CPU_THREAD, %rax
	leaq	resume_return(%rip), %r11

	/*
	 * Deal with SMAP here. A thread may be switched out at any point while
	 * it is executing. The thread could be under on_fault() or it could be
	 * pre-empted while performing a copy interruption. If this happens and
	 * we're not in the context of an interrupt which happens to handle
	 * saving and restoring rflags correctly, we may lose our SMAP related
	 * state.
	 *
	 * To handle this, as part of being switched out, we first save whether
	 * or not userland access is allowed ($PS_ACHK in rflags) and store that
	 * in t_useracc on the kthread_t and unconditionally enable SMAP to
	 * protect the system.
	 *
	 * Later, when the thread finishes resuming, we potentially disable smap
	 * if PS_ACHK was present in rflags. See uts/intel/ml/copy.s for
	 * more information on rflags and SMAP.
	 */
	pushfq
	popq	%rsi
	andq	$PS_ACHK, %rsi
	movq	%rsi, T_USERACC(%rax)
	call	smap_enable

	/*
	 * Take a moment to potentially clear the RSB buffer. This is done to
	 * prevent various Spectre variant 2 and SpectreRSB attacks. This may
	 * not be sufficient. Please see uts/intel/ml/retpoline.S for more
	 * information about this.
	 */
	call	x86_rsb_stuff

        /*
         * Take another moment to potentially clear the branch history buffer
         * (BHB). This is done to prevent recent discoveries that branch
         * history can also be trained to exploit certain compiler-generated
         * instruction sequences (known as "gadgets") to leak data
         * speculatively.  As with x86_rsb_stuff, see retpoline.S, and this
         * may not be sufficient.
         */
        call    x86_bhb_clear

	/*
	 * Save non-volatile registers, and set return address for current
	 * thread to resume_return.
	 *
	 * %r12 = t (new thread) when done
	 */
	SAVE_REGS(%rax, %r11)


	LOADCPU(%r15)				/* %r15 = CPU */
	movq	CPU_THREAD(%r15), %r13		/* %r13 = curthread */

	/*
	 * Call savectx if thread has installed context ops.
	 *
	 * Note that if we have floating point context, the save op
	 * (either fpsave_begin or fpxsave_begin) will issue the
	 * async save instruction (fnsave or fxsave respectively)
	 * that we fwait for below.
	 */
	cmpq	$0, T_CTX(%r13)		/* should current thread savectx? */
	je	.nosavectx		/* skip call when zero */

	movq	%r13, %rdi		/* arg = thread pointer */
	call	savectx			/* call ctx ops */
.nosavectx:

	/*
	 * Check that the curthread is not using the FPU while in the kernel.
	 */
	call	kernel_fpu_no_swtch

        /*
         * Call savepctx if process has installed context ops.
         */
	movq	T_PROCP(%r13), %r14	/* %r14 = proc */
        cmpq    $0, P_PCTX(%r14)         /* should current thread savepctx? */
        je      .nosavepctx              /* skip call when zero */

        movq    %r14, %rdi              /* arg = proc pointer */
        call    savepctx                 /* call ctx ops */
.nosavepctx:

	/*
	 * Temporarily switch to the idle thread's stack
	 */
	movq	CPU_IDLE_THREAD(%r15), %rax	/* idle thread pointer */

	/*
	 * Set the idle thread as the current thread
	 */
	movq	T_SP(%rax), %rsp	/* It is safe to set rsp */
	movq	%rax, CPU_THREAD(%r15)

	/*
	 * Switch in the hat context for the new thread
	 *
	 */
	GET_THREAD_HATP(%rdi, %r12, %r11)
	call	hat_switch

	/*
	 * Clear and unlock previous thread's t_lock
	 * to allow it to be dispatched by another processor.
	 */
	movb	$0, T_LOCK(%r13)

	/*
	 * IMPORTANT: Registers at this point must be:
	 *       %r12 = new thread
	 *
	 * Here we are in the idle thread, have dropped the old thread.
	 */
	ALTENTRY(_resume_from_idle)
	/*
	 * spin until dispatched thread's mutex has
	 * been unlocked. this mutex is unlocked when
	 * it becomes safe for the thread to run.
	 */
.lock_thread_mutex:
	lock
	btsl	$0, T_LOCK(%r12)	/* attempt to lock new thread's mutex */
	jnc	.thread_mutex_locked	/* got it */

.spin_thread_mutex:
	pause
	cmpb	$0, T_LOCK(%r12)	/* check mutex status */
	jz	.lock_thread_mutex	/* clear, retry lock */
	jmp	.spin_thread_mutex	/* still locked, spin... */

.thread_mutex_locked:
	/*
	 * Fix CPU structure to indicate new running thread.
	 * Set pointer in new thread to the CPU structure.
	 */
	LOADCPU(%r13)			/* load current CPU pointer */
	cmpq	%r13, T_CPU(%r12)
	je	.setup_cpu

	/* cp->cpu_stats.sys.cpumigrate++ */
	incq    CPU_STATS_SYS_CPUMIGRATE(%r13)
	movq	%r13, T_CPU(%r12)	/* set new thread's CPU pointer */

.setup_cpu:
	/*
	 * Setup rsp0 (kernel stack) in TSS to curthread's saved regs
	 * structure.  If this thread doesn't have a regs structure above
	 * the stack -- that is, if lwp_stk_init() was never called for the
	 * thread -- this will set rsp0 to the wrong value, but it's harmless
	 * as it's a kernel thread, and it won't actually attempt to implicitly
	 * use the rsp0 via a privilege change.
	 *
	 * Note that when we have KPTI enabled on amd64, we never use this
	 * value at all (since all the interrupts have an IST set).
	 */
	movq	CPU_TSS(%r13), %r14
#if !defined(__xpv)
	cmpq	$1, kpti_enable
	jne	1f
	leaq	CPU_KPTI_TR_RSP(%r13), %rax
	jmp	2f
1:
	movq	T_STACK(%r12), %rax
	addq	$REGSIZE+MINFRAME, %rax	/* to the bottom of thread stack */
2:
	movq	%rax, TSS_RSP0(%r14)
#else
	movq	T_STACK(%r12), %rax
	addq	$REGSIZE+MINFRAME, %rax	/* to the bottom of thread stack */
	movl	$KDS_SEL, %edi
	movq	%rax, %rsi
	call	HYPERVISOR_stack_switch
#endif	/* __xpv */

	movq	%r12, CPU_THREAD(%r13)	/* set CPU's thread pointer */
	mfence				/* synchronize with mutex_exit() */
	xorl	%ebp, %ebp		/* make $<threadlist behave better */
	movq	T_LWP(%r12), %rax	/* set associated lwp to  */
	movq	%rax, CPU_LWP(%r13)	/* CPU's lwp ptr */

	movq	T_SP(%r12), %rsp	/* switch to outgoing thread's stack */
	movq	T_PC(%r12), %r13	/* saved return addr */

	/*
	 * Call restorectx if context ops have been installed.
	 */
	cmpq	$0, T_CTX(%r12)		/* should resumed thread restorectx? */
	jz	.norestorectx		/* skip call when zero */
	movq	%r12, %rdi		/* arg = thread pointer */
	call	restorectx		/* call ctx ops */
.norestorectx:

	/*
	 * Call restorepctx if context ops have been installed for the proc.
	 */
	movq	T_PROCP(%r12), %rcx
	cmpq	$0, P_PCTX(%rcx)
	jz	.norestorepctx
	movq	%rcx, %rdi
	call	restorepctx
.norestorepctx:

	STORE_INTR_START(%r12)

	/*
	 * If we came into swtch with the ability to access userland pages, go
	 * ahead and restore that fact by disabling SMAP.  Clear the indicator
	 * flag out of paranoia.
	 */
	movq	T_USERACC(%r12), %rax	/* should we disable smap? */
	cmpq	$0, %rax		/* skip call when zero */
	jz	.nosmap
	xorq	%rax, %rax
	movq	%rax, T_USERACC(%r12)
	call	smap_disable
.nosmap:

	call	smt_mark

	/*
	 * Restore non-volatile registers, then have spl0 return to the
	 * resuming thread's PC after first setting the priority as low as
	 * possible and blocking all interrupt threads that may be active.
	 */
	movq	%r13, %rax	/* save return address */
	RESTORE_REGS(%r11)
	pushq	%rax		/* push return address for spl0() */
	call	__dtrace_probe___sched_on__cpu
	jmp	spl0

resume_return:
	/*
	 * Remove stack frame created in SAVE_REGS()
	 */
	addq	$CLONGSIZE, %rsp
	ret
	SET_SIZE(_resume_from_idle)
	SET_SIZE(resume)

	ENTRY(resume_from_zombie)
	movq	%gs:CPU_THREAD, %rax
	leaq	resume_from_zombie_return(%rip), %r11

	/*
	 * Save non-volatile registers, and set return address for current
	 * thread to resume_from_zombie_return.
	 *
	 * %r12 = t (new thread) when done
	 */
	SAVE_REGS(%rax, %r11)

	movq	%gs:CPU_THREAD, %r13	/* %r13 = curthread */

	/* clean up the fp unit. It might be left enabled */

#if defined(__xpv)		/* XXPV XXtclayton */
	/*
	 * Remove this after bringup.
	 * (Too many #gp's for an instrumented hypervisor.)
	 */
	STTS(%rax)
#else
	movq	%cr0, %rax
	testq	$CR0_TS, %rax
	jnz	.zfpu_disabled		/* if TS already set, nothing to do */
	fninit				/* init fpu & discard pending error */
	orq	$CR0_TS, %rax
	movq	%rax, %cr0
.zfpu_disabled:

#endif	/* __xpv */

	/*
	 * Temporarily switch to the idle thread's stack so that the zombie
	 * thread's stack can be reclaimed by the reaper.
	 */
	movq	%gs:CPU_IDLE_THREAD, %rax /* idle thread pointer */
	movq	T_SP(%rax), %rsp	/* get onto idle thread stack */

	/*
	 * Sigh. If the idle thread has never run thread_start()
	 * then t_sp is mis-aligned by thread_load().
	 */
	andq	$_BITNOT(STACK_ALIGN-1), %rsp

	/*
	 * Set the idle thread as the current thread.
	 */
	movq	%rax, %gs:CPU_THREAD

	/* switch in the hat context for the new thread */
	GET_THREAD_HATP(%rdi, %r12, %r11)
	call	hat_switch

	/*
	 * Put the zombie on death-row.
	 */
	movq	%r13, %rdi
	call	reapq_add

	jmp	_resume_from_idle	/* finish job of resume */

resume_from_zombie_return:
	RESTORE_REGS(%r11)		/* restore non-volatile registers */
	call	__dtrace_probe___sched_on__cpu

	/*
	 * Remove stack frame created in SAVE_REGS()
	 */
	addq	$CLONGSIZE, %rsp
	ret
	SET_SIZE(resume_from_zombie)

	ENTRY(resume_from_intr)
	movq	%gs:CPU_THREAD, %rax
	leaq	resume_from_intr_return(%rip), %r11

	/*
	 * Save non-volatile registers, and set return address for current
	 * thread to resume_from_intr_return.
	 *
	 * %r12 = t (new thread) when done
	 */
	SAVE_REGS(%rax, %r11)

	movq	%gs:CPU_THREAD, %r13	/* %r13 = curthread */
	movq	%r12, %gs:CPU_THREAD	/* set CPU's thread pointer */
	mfence				/* synchronize with mutex_exit() */
	movq	T_SP(%r12), %rsp	/* restore resuming thread's sp */
	xorl	%ebp, %ebp		/* make $<threadlist behave better */

	/*
	 * Unlock outgoing thread's mutex dispatched by another processor.
	 */
	xorl	%eax, %eax
	xchgb	%al, T_LOCK(%r13)

	STORE_INTR_START(%r12)

	call	smt_mark

	/*
	 * Restore non-volatile registers, then have spl0 return to the
	 * resuming thread's PC after first setting the priority as low as
	 * possible and blocking all interrupt threads that may be active.
	 */
	movq	T_PC(%r12), %rax	/* saved return addr */
	RESTORE_REGS(%r11);
	pushq	%rax			/* push return address for spl0() */
	call	__dtrace_probe___sched_on__cpu
	jmp	spl0

resume_from_intr_return:
	/*
	 * Remove stack frame created in SAVE_REGS()
	 */
	addq	$CLONGSIZE, %rsp
	ret
	SET_SIZE(resume_from_intr)

	ENTRY(thread_start)
	popq	%rax		/* start() */
	popq	%rdi		/* arg */
	popq	%rsi		/* len */
	movq	%rsp, %rbp
	INDIRECT_CALL_REG(rax)
	call	thread_exit	/* destroy thread if it returns. */
	/*NOTREACHED*/
	SET_SIZE(thread_start)

	ENTRY(thread_splitstack_run)
	pushq	%rbp			/* push base pointer */
	movq	%rsp, %rbp		/* construct frame */
	movq	%rdi, %rsp		/* set stack pinter */
	movq	%rdx, %rdi		/* load arg */
	INDIRECT_CALL_REG(rsi)		/* call specified function */
	leave				/* pop base pointer */
	ret
	SET_SIZE(thread_splitstack_run)

	/*
	 * Once we're back on our own stack, we need to be sure to set the
	 * value of rsp0 in the TSS back to our original stack:  if we gave
	 * up the CPU at all while on our split stack, the rsp0 will point
	 * to that stack from resume (above); if were to try to return to
	 * userland in that state, we will die absolutely horribly (namely,
	 * trying to iretq back to registers in a bunch of freed segkp).  We
	 * are expecting this to be called after T_STACK has been restored,
	 * but before we return.  It's okay if we are preempted in this code:
	 * when the new CPU picks us up, they will automatically set rsp0
	 * correctly, which is all we're trying to do here.
	 */
	ENTRY(thread_splitstack_cleanup)
	LOADCPU(%r8)
	movq	CPU_TSS(%r8), %r9
	cmpq	$1, kpti_enable
	jne	1f
	leaq	CPU_KPTI_TR_RSP(%r8), %rax
	jmp	2f
1:
	movq	CPU_THREAD(%r8), %r10
	movq	T_STACK(%r10), %rax
	addq	$REGSIZE+MINFRAME, %rax
2:
	movq	%rax, TSS_RSP0(%r9)
	ret
	SET_SIZE(thread_splitstack_cleanup)

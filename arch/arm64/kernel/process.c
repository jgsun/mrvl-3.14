/*
 * Based on arch/arm/kernel/process.c
 *
 * Original Copyright (C) 1995  Linus Torvalds
 * Copyright (C) 1996-2000 Russell King - Converted to ARM.
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>

#include <linux/compat.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/user.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/elfcore.h>
#include <linux/pm.h>
#include <linux/tick.h>
#include <linux/utsname.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/hw_breakpoint.h>
#include <linux/personality.h>
#include <linux/notifier.h>
#include <linux/debug_locks.h>
#include <linux/console.h>

#include <asm/compat.h>
#include <asm/cacheflush.h>
#include <asm/fpsimd.h>
#include <asm/mmu_context.h>
#include <asm/processor.h>
#include <asm/stacktrace.h>

static void setup_restart(void)
{
	/*
	 * Tell the mm system that we are going to reboot -
	 * we may need it to insert some 1:1 mappings so that
	 * soft boot works.
	 */
	setup_mm_for_reboot();

	/* Clean and invalidate caches */
	flush_cache_all();

	/* Turn D-cache off */
	cpu_cache_off();

	/* Push out any further dirty data, and ensure cache is empty */
	flush_cache_all();
}

void soft_restart(unsigned long addr)
{
	setup_restart();
	cpu_reset(addr);
}

#ifdef CONFIG_ARM64_FLUSH_CONSOLE_ON_RESTART
void arm_machine_flush_console(void)
{
	pr_info("\n");
	pr_emerg("Restarting %s\n", linux_banner);
	if (console_trylock()) {
		console_unlock();
		return;
	}

	mdelay(50);

	local_irq_disable();
	if (!console_trylock())
		pr_emerg("arm_restart: Console was locked! Busting\n");
	else
		pr_emerg("arm_restart: Console was locked!\n");
	debug_locks_off();
	console_unlock();
}
#else
void arm_machine_flush_console(void)
{
}
#endif

/*
 * Function pointers to optional machine specific functions
 */
void (*pm_power_off)(void);
EXPORT_SYMBOL_GPL(pm_power_off);

void (*arm_pm_restart)(enum reboot_mode reboot_mode, const char *cmd);
EXPORT_SYMBOL_GPL(arm_pm_restart);

/*
 * This is our default idle handler.
 */
void arch_cpu_idle(void)
{
	/*
	 * This should do all the clock switching and wait for interrupt
	 * tricks
	 */
	if (cpuidle_idle_call()) {
		cpu_do_idle();
		local_irq_enable();
	}
}

void arch_cpu_idle_enter(void)
{
	idle_notifier_call_chain(IDLE_START);
}

void arch_cpu_idle_exit(void)
{
	idle_notifier_call_chain(IDLE_END);
}

#ifdef CONFIG_HOTPLUG_CPU
void arch_cpu_idle_dead(void)
{
       cpu_die();
}
#endif

void machine_shutdown(void)
{
	disable_nonboot_cpus();
}

void machine_halt(void)
{
	local_irq_disable();
	smp_send_stop();
	while (1);
}

void machine_power_off(void)
{
	local_irq_disable();
	smp_send_stop();
	if (pm_power_off)
		pm_power_off();
}

void machine_restart(char *cmd)
{
	/* Disable interrupts first */
	local_irq_disable();
	smp_send_stop();

	/* Now call the architecture specific reboot code. */
	if (arm_pm_restart)
		arm_pm_restart(reboot_mode, cmd);

	/*
	 * Whoops - the architecture was unable to reboot.
	 */
	pr_info("Reboot failed -- System halted\n");
	while (1);
}

static void show_data(u64 addr, int nbytes, const char *name)
{
	unsigned long bottom, top, first;
	int i;

	/*
	 * don't attempt to dump non-kernel addresses or
	 * values that are probably just small negative numbers
	 */
	if (addr < PAGE_OFFSET || addr > -256UL)
		return;
	/*
	 * round address down to a 64 bit boundary
	 * and always dump a multiple of 64 bytes
	 */
	bottom = addr & ~(sizeof(u64) - 1);
	top = bottom + nbytes;
	pr_info("%s(0x%016lx to 0x%016lx)\n", name, bottom, top);

	for (first = bottom & ~31; first < top; first += 32) {
		unsigned long p;
		char str[sizeof(" 12345678") * 8 + 1];

		memset(str, ' ', sizeof(str));
		str[sizeof(str) - 1] = '\0';

		for (p = first, i = 0; i < 8 && p < top; i++, p += 4) {
			if (p >= bottom && p < top) {
				unsigned int val;
				if (__get_user(val, (unsigned int *)p) == 0)
					sprintf(str + i * 9, " %08x", val);
				else
					sprintf(str + i * 9, " ********");
			}
		}
		pr_info("%04lx:%s\n", first & 0xffff, str);
	}

	pr_info("\n");
}

static void show_extra_register_data(struct pt_regs *regs, int nbytes)
{
	int i, top_reg;
	u64 lr, sp;
	char s[4];
	mm_segment_t fs;

	if (compat_user_mode(regs)) {
		lr = regs->compat_lr;
		sp = regs->compat_sp;
		top_reg = 12;
	} else {
		lr = regs->regs[30];
		sp = regs->sp;
		top_reg = 29;
	}

	fs = get_fs();
	set_fs(KERNEL_DS);

	show_data(regs->pc - nbytes, nbytes * 2, "PC: ");
	show_data(lr - nbytes, nbytes * 2, "LR: ");
	show_data(regs->pstate - nbytes, nbytes * 2, "PSTATE: ");
	show_data(sp - nbytes, nbytes * 2, "SP: ");
	for (i = top_reg; i >= 0; i--) {
		sprintf(s, "%s%d: ", "R", i);
		show_data(regs->regs[i] - nbytes, nbytes * 2, s);
	}
	pr_info("\n");
	set_fs(fs);
}

void __show_regs(struct pt_regs *regs)
{
	int i, top_reg;
	u64 lr, sp;

	if (compat_user_mode(regs)) {
		lr = regs->compat_lr;
		sp = regs->compat_sp;
		top_reg = 12;
	} else {
		lr = regs->regs[30];
		sp = regs->sp;
		top_reg = 29;
	}

	show_regs_print_info(KERN_DEFAULT);
	print_symbol("PC is at %s\n", instruction_pointer(regs));
	print_symbol("LR is at %s\n", lr);
	pr_info("pc : [<%016llx>] lr : [<%016llx>] pstate: %08llx\n",
	       regs->pc, lr, regs->pstate);
	pr_info("sp : %016llx\n", sp);
	for (i = top_reg; i >= 0; i--) {
		pr_info("R%-2d: %016llx ", i, regs->regs[i]);
		if (i % 2 == 0)
			pr_info("\n");
	}
	pr_info("\n");
	show_extra_register_data(regs, 128);
}

void show_regs(struct pt_regs * regs)
{
	pr_info("\n");
	__show_regs(regs);
}

/*
 * Free current thread data structures etc..
 */
void exit_thread(void)
{
}

static void tls_thread_flush(void)
{
	asm ("msr tpidr_el0, xzr");

	if (is_compat_task()) {
		current->thread.tp_value = 0;

		/*
		 * We need to ensure ordering between the shadow state and the
		 * hardware state, so that we don't corrupt the hardware state
		 * with a stale shadow state during context switch.
		 */
		barrier();
		asm ("msr tpidrro_el0, xzr");
	}
}

void flush_thread(void)
{
	fpsimd_flush_thread();
	tls_thread_flush();
	flush_ptrace_hw_breakpoint(current);
}

void release_thread(struct task_struct *dead_task)
{
}

int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	fpsimd_preserve_current_state();
	*dst = *src;
	return 0;
}

asmlinkage void ret_from_fork(void) asm("ret_from_fork");

int copy_thread(unsigned long clone_flags, unsigned long stack_start,
		unsigned long stk_sz, struct task_struct *p)
{
	struct pt_regs *childregs = task_pt_regs(p);
	unsigned long tls = p->thread.tp_value;

	memset(&p->thread.cpu_context, 0, sizeof(struct cpu_context));

	if (likely(!(p->flags & PF_KTHREAD))) {
		*childregs = *current_pt_regs();
		childregs->regs[0] = 0;
		if (is_compat_thread(task_thread_info(p))) {
			if (stack_start)
				childregs->compat_sp = stack_start;
		} else {
			/*
			 * Read the current TLS pointer from tpidr_el0 as it may be
			 * out-of-sync with the saved value.
			 */
			asm("mrs %0, tpidr_el0" : "=r" (tls));
			if (stack_start) {
				/* 16-byte aligned stack mandatory on AArch64 */
				if (stack_start & 15)
					return -EINVAL;
				childregs->sp = stack_start;
			}
		}
		/*
		 * If a TLS pointer was passed to clone (4th argument), use it
		 * for the new thread.
		 */
		if (clone_flags & CLONE_SETTLS)
			tls = childregs->regs[3];
	} else {
		memset(childregs, 0, sizeof(struct pt_regs));
		childregs->pstate = PSR_MODE_EL1h;
		p->thread.cpu_context.x19 = stack_start;
		p->thread.cpu_context.x20 = stk_sz;
	}
	p->thread.cpu_context.pc = (unsigned long)ret_from_fork;
	p->thread.cpu_context.sp = (unsigned long)childregs;
	p->thread.tp_value = tls;

	ptrace_hw_copy_thread(p);

	return 0;
}

static void tls_thread_switch(struct task_struct *next)
{
	unsigned long tpidr, tpidrro;

	if (!is_compat_task()) {
		asm("mrs %0, tpidr_el0" : "=r" (tpidr));
		current->thread.tp_value = tpidr;
	}

	if (is_compat_thread(task_thread_info(next))) {
		tpidr = 0;
		tpidrro = next->thread.tp_value;
	} else {
		tpidr = next->thread.tp_value;
		tpidrro = 0;
	}

	asm(
	"	msr	tpidr_el0, %0\n"
	"	msr	tpidrro_el0, %1"
	: : "r" (tpidr), "r" (tpidrro));
}

/*
 * Thread switching.
 */
struct task_struct *__switch_to(struct task_struct *prev,
				struct task_struct *next)
{
	struct task_struct *last;

	fpsimd_thread_switch(next);
	tls_thread_switch(next);
	hw_breakpoint_thread_switch(next);
	contextidr_thread_switch(next);

	/*
	 * Complete any pending TLB or cache maintenance on this CPU in case
	 * the thread migrates to a different CPU.
	 */
	dsb();

	/* the actual thread switch */
	last = cpu_switch_to(prev, next);

	return last;
}

unsigned long get_wchan(struct task_struct *p)
{
	struct stackframe frame;
	unsigned long stack_page;
	int count = 0;
	if (!p || p == current || p->state == TASK_RUNNING)
		return 0;

	frame.fp = thread_saved_fp(p);
	frame.sp = thread_saved_sp(p);
	frame.pc = thread_saved_pc(p);
	stack_page = (unsigned long)task_stack_page(p);
	do {
		if (frame.sp < stack_page ||
		    frame.sp >= stack_page + THREAD_SIZE ||
		    unwind_frame(&frame))
			return 0;
		if (!in_sched_functions(frame.pc))
			return frame.pc;
	} while (count ++ < 16);
	return 0;
}

unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_int() & ~PAGE_MASK;
	return sp & ~0xf;
}

static unsigned long randomize_base(unsigned long base)
{
	unsigned long range_end = base + (STACK_RND_MASK << PAGE_SHIFT) + 1;
	return randomize_range(base, range_end, 0) ? : base;
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_base(mm->brk);
}

unsigned long randomize_et_dyn(unsigned long base)
{
	return randomize_base(base);
}

#ifdef CONFIG_COMPAT
unsigned long KSTK_ESP(struct task_struct *task)
{
	return (is_compat_thread(task_thread_info(task))) ?
		(task_pt_regs(task)->compat_sp) : (task_pt_regs(task)->sp);
}
#endif

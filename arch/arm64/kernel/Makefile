#
# Makefile for the linux kernel.
#

CPPFLAGS_vmlinux.lds	:= -DTEXT_OFFSET=$(TEXT_OFFSET)
AFLAGS_head.o		:= -DTEXT_OFFSET=$(TEXT_OFFSET)
CFLAGS_armv8_deprecated.o := -I$(src)

# Object file lists.
arm64-obj-y		:= cputable.o debug-monitors.o entry.o irq.o fpsimd.o	\
			   entry-fpsimd.o process.o ptrace.o setup.o signal.o	\
			   sys.o stacktrace.o time.o traps.o io.o vdso.o	\
			   hyp-stub.o psci.o cpu_ops.o insn.o cpuinfo.o

arm64-obj-$(CONFIG_COMPAT)		+= sys32.o kuser32.o signal32.o 	\
					   sys_compat.o 			\
					   ../../arm/kernel/opcodes.o
arm64-obj-$(CONFIG_MODULES)		+= arm64ksyms.o module.o
arm64-obj-$(CONFIG_SMP)			+= smp.o smp_spin_table.o topology.o
arm64-obj-$(CONFIG_HW_PERF_EVENTS)	+= perf_event.o
arm64-obj-$(CONFIG_HAVE_HW_BREAKPOINT)+= hw_breakpoint.o
arm64-obj-$(CONFIG_EARLY_PRINTK)	+= early_printk.o
arm64-obj-$(CONFIG_ARM64_CPU_SUSPEND)	+= sleep.o suspend.o
arm64-obj-$(CONFIG_KEXEC)		+= machine_kexec.o
arm64-obj-$(CONFIG_ARM_CPU_SUSPEND)	+= sleep.o suspend.o
arm64-obj-$(CONFIG_JUMP_LABEL)		+= jump_label.o
arm64-obj-$(CONFIG_ARMV8_DEPRECATED)	+= armv8_deprecated.o

obj-y					+= $(arm64-obj-y) vdso/
obj-m					+= $(arm64-obj-m)
head-y					:= head.o
extra-y					:= $(head-y) vmlinux.lds

# vDSO - this must be built first to generate the symbol offsets
$(call objectify,$(arm64-obj-y)): $(obj)/vdso/vdso-offsets.h
$(obj)/vdso/vdso-offsets.h: $(obj)/vdso

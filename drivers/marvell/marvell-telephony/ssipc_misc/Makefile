ccflags-y += -Idrivers/marvell/marvell-telephony/shmem
ccflags-y += -Idrivers/marvell/marvell-telephony/errorhandler

iodevk-objs := io_device.o
obj-$(CONFIG_MRVL_MMP_MODEM) += iodevk.o raw_misc.o

ssipcmisck-objs := ssipc_misc.o
obj-$(CONFIG_SSIPC_SUPPORT) += ssipcmisck.o

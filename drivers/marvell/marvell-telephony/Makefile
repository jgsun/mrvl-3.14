subdir-ccflags-y += -Idrivers/marvell/marvell-telephony/include
subdir-ccflags-y += -DEXPORT_SYMTAB
subdir-ccflags-y += -fno-pic
subdir-ccflags-y += -Werror

#follow dependency sequence
obj-$(CONFIG_MRVL_MMP_MODEM) += common/

obj-$(CONFIG_MRVL_MMP_MODEM) += cp_load/

obj-$(CONFIG_MRVL_MMP_MODEM) += shmem/

obj-$(CONFIG_MRVL_MMP_MODEM) += data_path/

obj-$(CONFIG_MRVL_MMP_MODEM) += errorhandler/

obj-$(CONFIG_MRVL_MMP_CM3) += m3_rm/

obj-$(CONFIG_MRVL_MMP_MODEM) += imlsdlog/

obj-$(CONFIG_MRVL_MMP_MODEM) += citty/

obj-$(CONFIG_MRVL_MMP_MODEM) += diag/

obj-$(CONFIG_MRVL_MMP_MODEM) += hwmap/

#obj-$(CONFIG_MRVL_MMP_MODEM) += cidatastub/

obj-$(CONFIG_MRVL_MMP_MODEM) += ccinetdev/

#obj-$(CONFIG_MRVL_MMP_MODEM) += cidatatty/

obj-$(CONFIG_MRVL_MMP_MODEM) += cimodemtty/

obj-$(CONFIG_MRVL_MMP_MODEM) += audio_stub/

obj-$(CONFIG_MRVL_MMP_MODEM) += ssipc_misc/

obj-$(CONFIG_MRVL_MMP_MODEM) += usim_event/

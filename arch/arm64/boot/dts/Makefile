dtb-$(CONFIG_ARCH_VEXPRESS) += rtsm_ve-aemv8a.dtb foundation-v8.dtb
dtb-$(CONFIG_ARCH_XGENE) += apm-mustang.dtb
dtb-$(CONFIG_ARCH_MMP) += pxa1928ff.dtb pxa1928concord.dtb pxa1928-psci.dtb pxa1928concord-discrete.dtb \
			  pxa1908-fpga.dtb pxa1918-fpga.dtb pxa1908-dkb.dtb pxa1908-cmtb.dtb pxa1908-ff.dtb \
			  pxa1936-qt.dtb pxa1936-fpga.dtb pxa1936-dkb-v10.dtb pxa1936-dkb-v20.dtb pxa1936-ff.dtb pxa1936-aloe-v01.dtb \
			  pxa1956-dkb-v10.dtb pxa1978-qt.dtb

targets += dtbs

DTB_NAMES := $(subst $\",,$(CONFIG_BUILD_ARM64_APPENDED_DTB_IMAGE_NAMES))
ifneq ($(DTB_NAMES),)
DTB_LIST := $(addsuffix .dtb,$(DTB_NAMES))
else
DTB_LIST := $(dtb-y)
endif
targets += $(DTB_LIST)

dtbs: $(addprefix $(obj)/, $(DTB_LIST))

clean-files := dts/*.dtb *.dtb

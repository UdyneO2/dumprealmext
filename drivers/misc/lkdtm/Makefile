# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_LKDTM)		+= lkdtm.o

lkdtm-$(CONFIG_LKDTM)		+= core.o
lkdtm-$(CONFIG_LKDTM)		+= bugs.o
lkdtm-$(CONFIG_LKDTM)		+= heap.o
lkdtm-$(CONFIG_LKDTM)		+= perms.o
lkdtm-$(CONFIG_LKDTM)		+= refcount.o
lkdtm-$(CONFIG_LKDTM)		+= rodata_objcopy.o
lkdtm-$(CONFIG_LKDTM)		+= usercopy.o

KCOV_INSTRUMENT_rodata.o	:= n
CFLAGS_rodata.o			+= $(DISABLE_LTO)

OBJCOPYFLAGS :=
OBJCOPYFLAGS_rodata_objcopy.o	:= \
<<<<<<< HEAD
			--rename-section .text=.rodata,alloc,readonly,load
=======
			--rename-section .noinstr.text=.rodata,alloc,readonly,load,contents
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
targets += rodata.o rodata_objcopy.o
$(obj)/rodata_objcopy.o: $(obj)/rodata.o FORCE
	$(call if_changed,objcopy)

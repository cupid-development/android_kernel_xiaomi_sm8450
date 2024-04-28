ifneq ($(KERNELRELEASE),)
	obj-$(CONFIG_TOUCHSCREEN_FST2) := fst2.o
	fst2-y := fts_lib/fts_flash.o \
			fts_lib/fts_io.o \
			fts_lib/fts_test.o \
			fts_proc.o \
			fts.o
else
	KDIR = $(OUT)/obj/KERNEL_OBJ
	CROSS_COMPILE = $(ANDROID_TOOLCHAIN)/aarch64-linux-android-
	CLANG = $(ANDROID_BUILD_TOP)/prebuilts/clang/host/linux-x86/clang-r370808
	REAL_CC = $(CLANG)/bin/clang
	AR = $(CLANG)/bin/llvm-ar
	LLVM_NM = $(CLANG)/bin/llvm-nm
	LD = $(CLANG)/bin/ld.lld

.PHONY: clean

default:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) REAL_CC=$(REAL_CC) CLANG_TRIPLE=aarch64-linux-gnu- AR=$(AR) LLVM_NM=$(LLVM_NM) LD=$(LD) -C $(KDIR) M=$(PWD) modules
clean:
	@rm -rf *.o* *.order *.symvers *.mod* .*.o.cmd .*.mod.o.cmd .*.ko.cmd .tmp_versions *.ko
	@find -name *.o | xargs rm -f
endif

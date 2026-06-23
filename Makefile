# ============================================================
# Makefile for pdd_bypass.ko ? K40 (alioth)
# ============================================================

KDIR       ?= /c/Users/wyf/Desktop/karnel/kernel_xiaomi_alioth
CROSS      ?= aarch64-none-elf-
ARCH       ?= arm64
MOD_DIR    ?= $(CURDIR)

# ?? MSYS2 ? /c/ ?? C:/???????????
ifneq ($(findstring MSYS,$(shell uname -s 2>/dev/null)),)
  export MSYS_NO_PATHCONV := 1
endif

obj-m      += pdd_bypass.o

.PHONY: all prepare_kernel modules deploy clean status unload

all: modules

modules:
	@echo "[*] KDIR = $(KDIR)"
	@echo "[*] CROSS = $(CROSS)"
	$(MAKE) -C "$(KDIR)" M="$(MOD_DIR)" ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) modules
	@echo "[+] pdd_bypass.ko ready"

prepare_kernel:
	cd "$(KDIR)" && $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) olddefconfig
	cd "$(KDIR)" && $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) prepare
	cd "$(KDIR)" && $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) modules_prepare

deploy:
	adb push "$(MOD_DIR)/pdd_bypass.ko" /data/local/tmp/
	adb shell "su -c 'rmmod pdd_bypass 2>/dev/null; insmod /data/local/tmp/pdd_bypass.ko'"
	adb shell "su -c 'dmesg | grep pdd_bypass | tail -3'"

status:
	adb shell "su -c 'lsmod | grep pdd_bypass || echo NOT_LOADED'"

unload:
	adb shell "su -c 'rmmod pdd_bypass && echo OK || echo FAIL'"

clean:
	$(MAKE) -C "$(KDIR)" M="$(MOD_DIR)" clean

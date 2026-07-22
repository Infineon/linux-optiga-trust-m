#/**
#* MIT License
#*
#* Copyright (c) 2026 Infineon Technologies AG
#*
#* Permission is hereby granted, free of charge, to any person obtaining a copy
#* of this software and associated documentation files (the "Software"), to deal
#* in the Software without restriction, including without limitation the rights
#* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#* copies of the Software, and to permit persons to whom the Software is
#* furnished to do so, subject to the following conditions:
#*
#* The above copyright notice and this permission notice shall be included in all
#* copies or substantial portions of the Software.
#*
#* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#* SOFTWARE
#
#*/
# Uncomment the following makro if you are running a 64-Bit Linux System

ARCH := $(shell dpkg --print-architecture)
BINDIR = bin
APPDIR = .

# Always choose mbedtls 4.x to build
TRUSTM = ../../trustm_lib

MBEDTLS_LIB    := $(TRUSTM)/external/mbedtls-4.x
TF_PSA_DIR     := $(MBEDTLS_LIB)/tf-psa-crypto
MBEDTLS_CONFIG := $(TRUSTM)/config/mbedtls_4.x_default_config.h
TF_PSA_CONFIG  := $(TRUSTM)/config/tf_psa_default_config.h

ifeq ($(ARCH), arm64)
LIB_INSTALL_DIR = /usr/lib/aarch64-linux-gnu
else
LIB_INSTALL_DIR = /usr/lib/arm-linux-gnueabihf
endif

INCDIR = ../include
INCDIR += ../include/pal
INCDIR += $(MBEDTLS_LIB)/include
INCDIR += $(MBEDTLS_LIB)/include/mbedtls
INCDIR += $(TRUSTM)/config
INCDIR += $(MBEDTLS_LIB)/library
INCDIR += $(TF_PSA_DIR)/include
INCDIR += $(TF_PSA_DIR)/utilities
INCDIR += $(TF_PSA_DIR)/dispatch
INCDIR += $(TF_PSA_DIR)/platform
INCDIR += $(TF_PSA_DIR)/drivers/builtin/include
INCDIR += $(TF_PSA_DIR)/drivers/builtin/src
INCDIR += $(TF_PSA_DIR)/core
INCDIR += $(TF_PSA_DIR)/extras




LIBDIR = ../src
LIBDIR += ../pal
LIBDIR += $(MBEDTLS_LIB)/library
LIBDIR += $(TF_PSA_DIR)/core
LIBDIR += $(TF_PSA_DIR)/platform
LIBDIR += $(TF_PSA_DIR)/utilities
LIBDIR += $(TF_PSA_DIR)/extras
LIBDIR += $(TF_PSA_DIR)/drivers/builtin/src


ifdef INCDIR
INCSRC := $(shell find $(INCDIR) -name '*.h')
INCDIR := $(addprefix -I ,$(INCDIR))
endif

ifdef LIBDIR
	LIBSRC += $(shell find $(LIBDIR) -name '*.c') 
	# Select the correct PAL crypt for the requested Mbed TLS variant.
	# pal_crypt_psa.c targets Mbed TLS 4.x / TF-PSA-Crypto (PSA Crypto API),
	# whereas the original pal_crypt_mbedtls.c targets Mbed TLS 2.x / 3.x.
	LIBSRC := $(filter-out %/pal_crypt_mbedtls.c,$(LIBSRC))
	LIBOBJ := $(patsubst %.c,%.o,$(LIBSRC))
	LIB = libtrustm_update.so
endif


ifdef OTHDIR
	OTHSRC := $(shell find $(OTHDIR) -name '*.c')
	OTHOBJ := $(patsubst %.c,%.o,$(OTHSRC))
endif

ifdef APPDIR
	APPSRC := $(shell find $(APPDIR) -name '*.c')
	APPOBJ := $(patsubst %.c,%.o,$(APPSRC))
	APPS := $(patsubst %.c,%,$(APPSRC))
endif


CC = gcc
DEBUG = -g

CFLAGS = -c
#CFLAGS += $(DEBUG)
CFLAGS += $(INCDIR)
CFLAGS += -Wall
CFLAGS += -Wno-pointer-sign
ifeq ($(ARCH), arm64)
CFLAGS += -fPIC
endif
CFLAGS += -DMBEDTLS_USER_CONFIG_FILE=\"../../$(MBEDTLS_CONFIG)\"
CFLAGS += -DTF_PSA_CRYPTO_USER_CONFIG_FILE=\"../../$(TF_PSA_CONFIG)\"


LDFLAGS += -lpthread

LDFLAGS_1 = -L$(BINDIR) -Wl,-R$(BINDIR)
LDFLAGS_1 += -ltrustm_update

.Phony :  install all clean

all :  $(BINDIR)/$(LIB) $(APPS) 

install:
	@echo "Create symbolic link to trustm_lib $(LIB_INSTALL_DIR)/$(LIB)"
	@ln -s $(realpath $(BINDIR)/$(LIB)) $(LIB_INSTALL_DIR)/$(LIB)
	
uninstall: clean
	@echo "Removing trustm_lib $(LIB_INSTALL_DIR)/$(LIB)"
	@rm -rf $(LIB_INSTALL_DIR)/$(LIB)
	
clean :
	@echo "Removing *.o from $(LIBDIR)" 
	@rm -rf $(LIBOBJ)
	@echo "Removing *.o from $(OTHDIR)" 
	@rm -rf $(OTHOBJ)
	@echo "Removing *.o from $(APPDIR)"
	@rm -rf $(APPOBJ)
	@echo "Removing all application from $(APPDIR)"	
	@rm -rf $(APPS)
	@echo "Removing all application from $(BINDIR)"	
	@rm -rf bin/*
	@echo "Removing all hidden files"	
	@rm -rf .trustm_*
	@echo "Removing trustm_lib $(LIB_INSTALL_DIR)/$(LIB)"
	@sudo rm -rf $(LIB_INSTALL_DIR)/$(LIB)


$(APPS): %: $(OTHOBJ) $(INCSRC) $(BINDIR)/$(LIB) %.o
	@echo "******* Linking $@ "
	@mkdir -p bin
	@$(CC) $@.o $(LDFLAGS_1) $(LDFLAGS) $(OTHOBJ) -o $@
	@mv $@ bin/.

$(BINDIR)/$(LIB): %: $(LIBOBJ) $(INCSRC)
	@echo "******* Linking $@ "
	@mkdir -p bin
	@$(CC) $(LDFLAGS) $(LIBOBJ) -shared -o $@

$(LIBOBJ): %.o: %.c $(INCSRC)
	@echo "+++++++ Generating lib object: $< "
	@$(CC) $(CFLAGS) $< -o $@



%.o: %.c $(INCSRC)
	@echo "------- Generating application objects: $< "
	@$(CC) $(CFLAGS) $< -o $@

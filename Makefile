#/**
#* MIT License
#*
#* Copyright (c) 2020 Infineon Technologies AG
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

TRUSTM =linux-driver-optiga-trust-m

BUILD_FOR_RPI = YES
BUILD_FOR_ULTRA96 = NO
DRIVER_PROJECT_DIR= $(TRUSTM)/projects/linux_driver
#~ PALDIR =  $(TRUSTM)/pal/linux_driver
#~ LIBDIR = $(TRUSTM)/optiga/util
#~ LIBDIR += $(TRUSTM)/optiga/crypt
#~ LIBDIR += $(TRUSTM)/optiga/comms
#~ LIBDIR += $(TRUSTM)/optiga/common
#~ LIBDIR += $(TRUSTM)/optiga/cmd
#~ #LIBDIR += $(TRUSTM)/externals/mbedtls
LIBDIR += trustm_helper

#OTHDIR = $(TRUSTM)/examples/optiga
 
BINDIR = bin
APPDIR = linux_example
ENGDIR = trustm_engine
LIB_INSTALL_DIR = /usr/lib/arm-linux-gnueabihf
ENGINE_INSTALL_DIR = $(LIB_INSTALL_DIR)/engines-1.1

INCDIR = $(TRUSTM)/optiga/include
INCDIR += $(TRUSTM)/optiga/include/optiga
INCDIR += $(TRUSTM)/optiga/include/optiga/ifx_i2c
INCDIR += $(TRUSTM)/optiga/include/optiga/comms
INCDIR += $(TRUSTM)/optiga/include/optiga/common
INCDIR += $(TRUSTM)/optiga/include/optiga/cmd
INCDIR += $(TRUSTM)/optiga/include/optiga/pal
INCDIR += $(TRUSTM)/pal/linux_driver
INCDIR += $(TRUSTM)/pal/
INCDIR += trustm_helper/include
INCDIR += trustm_engine



ifdef INCDIR
INCSRC := $(shell find $(INCDIR) -name '*.h')
INCDIR := $(addprefix -I ,$(INCDIR))
endif

ifdef LIBDIR
	ifdef PALDIR
	        LIBSRC =  $(PALDIR)/pal.c
	        LIBSRC += $(PALDIR)/pal_gpio.c
	        LIBSRC += $(PALDIR)/pal_i2c.c
			LIBSRC += $(PALDIR)/pal_logger.c
			LIBSRC += $(PALDIR)/pal_os_datastore.c
	        LIBSRC += $(PALDIR)/pal_os_event.c
        	LIBSRC += $(PALDIR)/pal_os_lock.c
	        LIBSRC += $(PALDIR)/pal_os_timer.c
	        LIBSRC += $(PALDIR)/pal_os_memory.c
			LIBSRC += $(TRUSTM)/pal/pal_crypt_openssl.c
	        ifeq ($(BUILD_FOR_RPI), YES)
	                LIBSRC += $(PALDIR)/target/rpi3/pal_ifx_i2c_config.c
        	endif

	        ifeq ($(BUILD_FOR_ULTRA96), YES)
                	LIBSRC += $(PALDIR)/target/ultra96/pal_ifx_i2c_config.c
        	endif
	endif

	LIBSRC += $(shell find $(LIBDIR) -name '*.c') 
	LIBOBJ := $(patsubst %.c,%.o,$(LIBSRC))
	LIB = libtrustm.so
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

ifdef ENGDIR
	ENGSRC := $(shell find $(ENGDIR) -name '*.c')
	ENGOBJ := $(patsubst %.c,%.o,$(ENGSRC))
	ENG = trustm_engine.so
endif

CC = gcc
DEBUG = -g

CFLAGS += -c
#CFLAGS += $(DEBUG)
CFLAGS += $(INCDIR)
CFLAGS += -Wall
CFLAGS += -DENGINE_DYNAMIC_SUPPORT
CFLAGS += -DOPTIGA_LINUX_DRIVER_MODE
CFLAGS += -DOPTIGA_OPEN_CLOSE_DISABLED
#CFLAGS += -DMODULE_ENABLE_DTLS_MUTUAL_AUTH

LDFLAGS += -lpthread
LDFLAGS += -lssl
LDFLAGS += -lcrypto
LDFLAGS += -lrt

LDFLAGS_1 = -L$(BINDIR) -Wl,-R$(BINDIR)
LDFLAGS_1 += -ltrustm
LDFLAGS_1 += -loptiga_service_layer

.Phony : install uninstall all clean all_with_driver uninstall_with_driver

all : $(BINDIR)/$(LIB) $(APPS) $(BINDIR)/$(ENG)
#~ all : $(BINDIR)/$(LIB) $(APPS) 


all_with_driver: | make_lib install_driver set_driver_permission all
uninstall_with_driver: | clear_driver_lib remove_driver uninstall

clear_driver_lib: 
	cd $(DRIVER_PROJECT_DIR) && make clean
make_lib:
	cd $(DRIVER_PROJECT_DIR) && make 
install_driver:
	cd $(DRIVER_PROJECT_DIR) && make install-optiga-linux-driver
set_driver_permission:
	sudo chown pi:pi /dev/optigatrustmv3	
remove_driver:
	cd $(DRIVER_PROJECT_DIR) && make uninstall-optiga-linux-driver
	
install:
	@echo "Create symbolic link to trustx_lib $(LIB_INSTALL_DIR)/$(LIB)"
	@ln -s $(realpath $(BINDIR)/$(LIB)) $(LIB_INSTALL_DIR)/$(LIB)
	@echo "Create symbolic link to the openssl engine $(ENGINE_INSTALL_DIR)/$(ENG)"
	@ln -s $(realpath $(BINDIR)/$(ENG)) $(ENGINE_INSTALL_DIR)/$(ENG)
	
uninstall: clean
	@echo "Removing trustm_lib $(LIB_INSTALL_DIR)/$(LIB)"
	@-rm $(LIB_INSTALL_DIR)/$(LIB)
	@echo "Removing openssl symbolic link from $(ENGINE_INSTALL_DIR)"	
	@-rm $(ENGINE_INSTALL_DIR)/$(ENG)

clean :
	@echo "Removing *.o from $(LIBDIR)" 
	@rm -rf $(LIBOBJ)
	@echo "Removing *.o from $(OTHDIR)" 
	@rm -rf $(OTHOBJ)
	@echo "Removing *.o from $(APPDIR)"
	@rm -rf $(APPOBJ)
	@echo "Removing *.o from $(ENGDIR)"
	@rm -rf $(ENGOBJ)
	@echo "Removing all application from $(APPDIR)"	
	@rm -rf $(APPS)
	@echo "Removing all application from $(BINDIR)"	
	@rm -rf bin/*
	@echo "Removing all hidden files"	
	@rm -rf .trustm_*

$(BINDIR)/$(ENG): %: $(ENGOBJ) $(INCSRC) $(BINDIR)/$(LIB)
	@echo "******* Linking $@ "
	@mkdir -p bin
	@$(CC) $(LDFLAGS_1) $(LDFLAGS) $(ENGOBJ) -shared -o $@

$(APPS): %: $(OTHOBJ) $(INCSRC) $(BINDIR)/$(LIB) %.o
	@echo "******* Linking $@ "
	@mkdir -p bin
	@$(CC) $@.o $(LDFLAGS_1) $(LDFLAGS) $(OTHOBJ) -o $@
	@cp $@ bin/.

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

CLANG  := clang
CFLAGS := -O2 -g -Wall -target bpf -std=gnu23

SRC_DIR := .
OBJ_DIR := obj

BPF_NAME := wg
SOURCE   := $(SRC_DIR)/$(BPF_NAME).c
HEADERS  := $(shell find $(SRC_DIR) -name "*.h")

LE_OBJ_FILE := $(OBJ_DIR)/$(BPF_NAME)_le.o
BE_OBJ_FILE := $(OBJ_DIR)/$(BPF_NAME)_be.o
WOLF_LE_OBJ_FILE := $(OBJ_DIR)/wolf_le.o
WOLF_BE_OBJ_FILE := $(OBJ_DIR)/wolf_be.o

LE_FLAG := -mlittle-endian
BE_FLAG := -mbig-endian

.DEFAULT_GOAL := wireguard

all: wireguard wolfguard

wireguard: le be

le: $(LE_OBJ_FILE)

be: $(BE_OBJ_FILE)

wolfguard: wolf-le wolf-be

wolf: wolfguard

wolf-le: $(WOLF_LE_OBJ_FILE)

wolf-be: $(WOLF_BE_OBJ_FILE)

.PHONY: all wireguard wolfguard le be wolf wolf-le wolf-be clean

clean:
	@rm -rf $(OBJ_DIR)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

define BPF_COMPILE
$(1): ENDIAN_FLAG := $(2)
$(1): BACKEND_FLAG := $(3)
$(1): $(SOURCE) $(HEADERS) | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) $$(ENDIAN_FLAG) $$(BACKEND_FLAG) -c $$< -o $$@
endef

$(eval $(call BPF_COMPILE,$(LE_OBJ_FILE),$(LE_FLAG)))
$(eval $(call BPF_COMPILE,$(BE_OBJ_FILE),$(BE_FLAG)))
$(eval $(call BPF_COMPILE,$(WOLF_LE_OBJ_FILE),$(LE_FLAG),-DWOLFGUARD))
$(eval $(call BPF_COMPILE,$(WOLF_BE_OBJ_FILE),$(BE_FLAG),-DWOLFGUARD))

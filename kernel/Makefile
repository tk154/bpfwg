CLANG  := clang
CFLAGS := -O2 -g -Wall -target bpf -std=gnu23

SRC_DIR := .
OBJ_DIR := obj

BPF_NAME := wg
SOURCE   := $(SRC_DIR)/$(BPF_NAME).c
HEADERS  := $(shell find $(SRC_DIR) -name "*.h")

LE_OBJ_FILE := $(OBJ_DIR)/$(BPF_NAME)_le.o
BE_OBJ_FILE := $(OBJ_DIR)/$(BPF_NAME)_be.o

LE_FLAG := -mlittle-endian
BE_FLAG := -mbig-endian

all: le be

le: ENDIAN_FLAG := $(LE_FLAG)
le: $(LE_OBJ_FILE)

be: ENDIAN_FLAG := $(BE_FLAG)
be: $(BE_OBJ_FILE)

clean:
	@rm -rf $(OBJ_DIR)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

define BPF_COMPILE
$(1): $(SOURCE) $(HEADERS) | $(OBJ_DIR)
	$(CLANG) $(CFLAGS) $$(ENDIAN_FLAG) -c $$< -o $$@
endef

$(eval $(call BPF_COMPILE,$(LE_OBJ_FILE)))
$(eval $(call BPF_COMPILE,$(BE_OBJ_FILE)))

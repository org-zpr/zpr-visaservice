ZPLC ?= zplc
KEY := zpr-rsa-key.pem

OBJS := conform-policy.bin

info:
	@echo Makefile to help with compiling the ZPR policies
	@echo from source.
	@echo
	@echo make clean - removes all the .bin policy files
	@echo make all   - recompiles out of date policy files
	@echo
	@echo Requires that \'zplc\' the ZPL compiler is in your path.
	@echo Or you can set path to zplc by setting ZPLC variable.
	@echo

all: $(OBJS)

clean:
	rm -f $(OBJS)


%.bin: %.zpl %.zplc
	$(ZPLC) -k $(KEY) $<


rebuild: clean all

.PHONY: all clean rebuild

.DEFAULT_GOAL: info

CC_HOST ?= cc
CC_X64  ?= x86_64-w64-mingw32-gcc
CC_X86  ?= i686-w64-mingw32-gcc
BOFFLAGS = -c -O2 -fno-builtin -Wall -Wextra -Ibof

RELAY_URL ?= http://127.0.0.1:8090

all: relay

relay:
	$(CC_HOST) -O2 -Wall -Wextra -o dist/bits-udc2-relay relay/main.c -lpthread

udc2:
	@mkdir -p dist
	@if [ "$(RELAY_URL)" != "$$(cat dist/.relay_url 2>/dev/null)" ]; then \
		echo 'relay URL changed — rebuilding UDC2 BOFs'; \
		rm -f dist/udc2_bits.x64.o dist/udc2_bits.x86.o dist/udc2_harness.exe; \
		printf '%s' "$(RELAY_URL)" > dist/.relay_url; \
	fi
	@$(MAKE) dist/udc2_bits.x64.o
	@$(MAKE) dist/udc2_bits.x86.o
	@printf '%s' "$(RELAY_URL)" > dist/.relay_url

dist/udc2_bits.x64.o: bof/udc2_bits.c
	$(CC_X64) $(BOFFLAGS) '-DBITS_UDC2_RELAY_URL="$(RELAY_URL)"' bof/udc2_bits.c -o $@

dist/udc2_bits.x86.o: bof/udc2_bits.c
	$(CC_X86) $(BOFFLAGS) '-DBITS_UDC2_RELAY_URL="$(RELAY_URL)"' bof/udc2_bits.c -o $@

harness: dist/udc2_harness.exe

dist/udc2_harness.exe: bof/udc2_bits.c bof/harness_main.c
	$(CC_X64) -O2 -fno-builtin -Wall -DBOF_HARNESS '-DBITS_UDC2_RELAY_URL="$(RELAY_URL)"' -Ibof -o $@ bof/harness_main.c bof/udc2_bits.c

clean:
	rm -f dist/bits-udc2-relay dist/udc2_bits.*.o dist/.relay_url

.PHONY: all relay udc2 clean

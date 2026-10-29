CC = clang
FUZZ_SECONDS ?= 60
CFLAGS = -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
	-Duint24_t=uint32_t -Dint24_t=int32_t -Ishim -I../../src/include -I../../src -I../../src/tls/includes
TARGETS = json xml url base64 asn1 pcap x509 ws tls
SRC = ../../src

json_SRC = $(SRC)/parsers/json.c
xml_SRC = $(SRC)/parsers/xml.c
url_SRC = $(SRC)/parsers/url.c
base64_SRC = $(SRC)/tls/core/base64.c
asn1_SRC = $(SRC)/tls/core/asn1.c
pcap_SRC =
ws_SRC =
x509_SRC = x509_stubs.c $(SRC)/tls/core/x509.c $(SRC)/tls/core/asn1.c $(SRC)/tls/core/base64.c

.PHONY: all run $(TARGETS:%=run-%) clean

all: $(TARGETS:%=bin/fuzz_%)

bin/fuzz_ws: fuzz_ws.c ws_unit.py ../host/altcp_ws/mock.h $(SRC)/apps/altcp_ws/altcp_ws.c
	mkdir -p bin
	python3 ws_unit.py $(SRC)/apps/altcp_ws/altcp_ws.c bin/ws_unit.c
	$(CC) $(filter-out -I%,$(CFLAGS)) -Ibin -o $@ $<

bin/fuzz_tls: fuzz_tls.c ../host/tls_signatures/run.py ../host/tls_signatures/mock.h $(SRC)/tls/core/handshake.c \
		$(SRC)/tls/core/x509.c $(SRC)/tls/core/key.c $(SRC)/tls/core/base64.c
	mkdir -p bin/tls
	python3 ../host/tls_signatures/run.py bin/tls
	$(CC) $(filter-out -I% -D%,$(CFLAGS)) -Wno-array-parameter -Ibin/tls -I$(SRC)/tls/includes -I$(SRC)/tls/core \
		-o $@ $< $(SRC)/tls/core/asn1.c $(SRC)/tls/core/base64.c

bin/fuzz_%: fuzz_%.c $(wildcard ../../src/parsers/*.c ../../src/tls/core/*.c) x509_stubs.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< $($*_SRC)

run: $(TARGETS:%=run-%)

$(TARGETS:%=run-%): run-%: bin/fuzz_%
	mkdir -p corpus/$* out/$* out/artifacts
	./bin/fuzz_$* -max_total_time=$(FUZZ_SECONDS) -print_final_stats=1 -artifact_prefix=out/artifacts/$*- \
		out/$* corpus/$*

clean:
	rm -rf bin out

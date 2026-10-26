SUITES = sockets raw tls records server perf

.PHONY: all clean $(SUITES)

all: $(SUITES)

$(SUITES):
	$(MAKE) -C $@

clean:
	$(foreach s,$(SUITES),$(MAKE) -C $(s) clean &&) true

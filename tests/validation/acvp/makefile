.PHONY: all clean

# Keep the historical entry point useful, but do not build the old aggregate
# ACVPRUN service.  Each primitive now has its own gated program under
# tests/acvp so CI can run them concurrently.
all:
	$(MAKE) -C ../../acvp all

clean:
	$(MAKE) -C ../../acvp clean

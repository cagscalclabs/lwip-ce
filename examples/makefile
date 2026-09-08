#-----------------------------------------------
# This makefile builds all lwIP release examples
#-----------------------------------------------

MAKEFILES = $(wildcard */makefile)

all clean .PHONY: $(MAKEFILES)

$(MAKEFILES):
	$(MAKE) -C $(dir $@) $(or $(MAKECMDGOALS),$(findstring debug,$@))

.PHONY: all clean

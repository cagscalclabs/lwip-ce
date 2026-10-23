TICALCS = ticalcs2 ticables2 tifiles2 ticonv glib-2.0

bin/calclink: calclink.c
	@mkdir -p bin
	$(CC) -O2 -Wall -Wextra $< -o $@ $$(pkg-config --cflags --libs $(TICALCS))

clean:
	rm -rf bin

.PHONY: clean

FPC ?= fpc
FLAGS = -Mobjfpc -Sh -O2 -g -gl -vewn -Fu./src
SOURCES = $(wildcard src/*.pas) src/sentinel.lpr

.PHONY: all test integration smoke clean
all: bin/sentinel

bin/sentinel: $(SOURCES)
	mkdir -p bin build/units
	$(FPC) $(FLAGS) -FUbuild/units -FEbin src/sentinel.lpr

bin/test_suite: tests/test_suite.lpr $(SOURCES)
	mkdir -p bin build/test-units
	$(FPC) $(FLAGS) -Cr -Co -Ci -Sa -FUbuild/test-units -FEbin tests/test_suite.lpr

test: bin/test_suite
	./bin/test_suite

bin/test_server: tests/test_server.lpr $(SOURCES)
	mkdir -p bin build/server-test-units
	$(FPC) $(FLAGS) -Cr -Co -Ci -Sa -FUbuild/server-test-units -FEbin tests/test_server.lpr

integration: bin/test_server
	python3 tests/integration.py

bin/live_smoke: tests/live_smoke.lpr $(SOURCES)
	mkdir -p bin build/smoke-units
	$(FPC) $(FLAGS) -FUbuild/smoke-units -FEbin tests/live_smoke.lpr

smoke: bin/live_smoke
	./bin/live_smoke

clean:
	rm -rf bin build

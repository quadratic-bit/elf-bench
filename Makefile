CXX ?= c++

CXXFLAGS ?= -O3 -DNDEBUG -std=c++17 -march=native

LLVM_CONFIG ?= llvm-config

LLVM_CXXFLAGS    := $(shell $(LLVM_CONFIG) --cxxflags)
LLVM_LDFLAGS     := $(shell $(LLVM_CONFIG) --ldflags)
LLVM_LIBS        := $(shell $(LLVM_CONFIG) --libs object support)
LLVM_SYSTEM_LIBS := $(shell $(LLVM_CONFIG) --system-libs)

.PHONY: all clean

all: bench-lief bench-elfio bench-llvm make-fixtures

bench-lief: lief.cpp common.hpp
	$(CXX) $(CXXFLAGS) \
		-I$(LIEF_INCLUDEDIR) \
		-I$(LIEF_LIBDIR)/include \
		lief.cpp -o $@ \
		-L$(LIEF_LIBDIR) -Wl,-rpath,$(LIEF_LIBDIR) -lLIEF

bench-elfio: elfio.cpp common.hpp
	$(CXX) $(CXXFLAGS) \
		-I$(ELFIO_INCLUDEDIR) \
		elfio.cpp -o $@

bench-llvm: llvm.cpp common.hpp
	$(CXX) \
		$(LLVM_CXXFLAGS) \
		$(CXXFLAGS) \
		-fexceptions \
		llvm.cpp -o $@ \
		$(LLVM_LDFLAGS) \
		$(LLVM_LIBS) \
		$(LLVM_SYSTEM_LIBS)

make-fixtures: make-fixtures.cpp
	$(CXX) $(CXXFLAGS) \
		-I$(ELFIO_INCLUDEDIR) \
		make-fixtures.cpp -o $@

clean:
	rm -f bench-lief bench-elfio make-fixtures bench-llvm

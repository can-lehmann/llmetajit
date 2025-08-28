all: bin/llmetajit examples/bf.ll

run: all
	./bin/llmetajit examples/bf.ll

bin/llmetajit: llmetajit.cpp
	clang++ -g `llvm-config --libs --cflags` -o $@ $<

examples/%.ll: examples/%.cpp
	clang++ -Xclang -disable-O0-optnone -c -emit-llvm -S -o $@ $<
	opt -passes=lower-switch,instcombine,dce -o $@ -S $@


all: hawk

hawk: hawk.c vm.c vmgen.c bc.h types.h
	clang -std=c23 -g -o hawk hawk.c vm.c

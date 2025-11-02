all: hawk

hawk: hawk.c vm.c vmgen.c bc.h types.h types.c
	clang -std=c23 -g -o hawk hawk.c vm.c types.c

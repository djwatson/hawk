all: readbc

readbc: readbc.cpp
	clang  -O3 -o readbc readbc.cpp -lstdc++ 

cloc:
	cloc --by-file readbc.cpp bc.scm

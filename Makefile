all: readbc

readbc: readbc.cpp
	clang -gdwarf-3 -O3 -o readbc readbc.cpp -lstdc++

cloc:
	cloc --by-file readbc.cpp bc.scm

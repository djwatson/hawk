all: boom

SUFFIXES += .d

NODEPS:= clean cloc format tidy

SOURCES:=readbc.cpp bytecode.cpp vm.cpp boom.cpp record.cpp ir.cpp snap.cpp replay.cpp
OBJS:=$(patsubst %.cpp,%.o,$(SOURCES))
HEADERS:=$(patsubst %.cpp,%.h,$(SOURCES))

DEPFILES:=$(patsubst %.cpp,%.d,$(SOURCES))

CXX=clang

CXXFLAGS=-O3 -gdwarf-3 

ifeq (0, $(words $(findstring $(MAKECMDGOALS), $(NODEPS))))
	-include $(DEPFILES)
endif

%.d: %.cpp
	$(CXX) $(CXXFLAGS) -MM -MT '$(patsubst %.cpp,%.o,$<)' $< -MF $@

%.o: %.cpp %.d %.h
	$(CXX) $(CXXFLAGS) -o $@ -c $<

boom: $(OBJS)
	$(CXX) $(CXXFLAGS) -o boom $(OBJS) -lstdc++ 

cloc:
	cloc --by-file $(SOURCES) bc.scm $(HEADERS)

clean:
	rm -rf $(DEPFILES) $(OBJS) boom

format:
	clang-format -i *.h *.cpp

tidy:
	clang-tidy -checks=clang-diagnostic-*,clang-analyzer-*,bugprone*,modernize*,performance*,readability-*,-modernize-avoid-c-arrays,-readability-identifier-length,-modernize-use-trailing-return-type $(SOURCES)

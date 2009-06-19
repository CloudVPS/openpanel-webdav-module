include makeinclude

OBJ	= main.o

all: module.xml action

action: $(OBJ)
	$(LD) $(LDFLAGS) -o action $(OBJ) -L/var/opencore/api/grace/lib -L../opencore/api/grace/lib -lgrace-coreapi $(LIBS)

module.xml: module.def
	mkmodulexml < module.def > module.xml

clean:
	rm -f *.o
	rm -f action
	rm -f module.xml

allclean: clean
	rm -f makeinclude configure.paths platform.h
	
install: all
	./makeinstall

makeinclude:
	@echo please run ./configure
	@false

SUFFIXES: .cpp .o
.cpp.o:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -I../opencore/api/grace/include -c $<

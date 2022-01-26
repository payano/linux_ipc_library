CFLAGS       = -O2 #-pedantic -Wall -Wextra -ggdb3
LDFLAGS =  -lrt -lpthread -lipc

INCPATH = ../

SOURCES = $(shell echo *.c)
HEADERS = $(shell echo *.h)
OBJECTS=$(SOURCES:.cpp=.o)

TARGET=ipc_com_example

all: $(TARGET)

clean:
	rm -f $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CC) -L$(INCPATH) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

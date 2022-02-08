CFLAGS       = -fPIC -g -O2 -pedantic -Wall -Wextra -Wpedantic #-ggdb3
LDFLAGS      = -shared -lpthread -lrt
#MACROS       = -D DEBUG

SOURCES = $(shell echo *.c)
HEADERS = $(shell echo *.h)
OBJECTS=$(SOURCES:.cpp=.o)

TARGET=libipc.so

all: $(TARGET)

clean:
	rm -f $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS) ${MACROS}

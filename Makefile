TARGET = suexec
SOURCES = suexec.c

override DEFINES +=
override INCLUDES +=
override LDFLAGS += -lconfuse

$(TARGET): $(SOURCES)
	$(CC) $(DEFINES) $(INCLUDES) $(LDFLAGS) $(SOURCES) -o$(TARGET)

clean:
	rm -f $(TARGET)

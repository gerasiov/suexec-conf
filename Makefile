TARGET = suexec
SOURCES = suexec.c

override DEFINES +=
override INCLUDES +=
override LDFLAGS += -lconfuse

all: $(TARGET) suexec.conf.5

$(TARGET): $(SOURCES)
	$(CC) $(DEFINES) $(INCLUDES) $(LDFLAGS) $(SOURCES) -o$(TARGET)

suexec.conf.5: suexec.conf.sgml
	docbook-to-man $< > $@

clean:
	rm -f $(TARGET) suexec.conf.5

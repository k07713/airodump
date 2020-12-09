TARGET = airodump
LDLIBS+= -lpcap

all: $(TARGET)

clean:
	rm -f $(TARGET) *.o

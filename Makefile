CC = gcc
CFLAGS = -Wall -O2
LIBS = -lssl -lcrypto
TARGET = finance_tracker

all: $(TARGET)

$(TARGET): finance_tracker.c
	 $(CC) $(CFLAGS) -o $(TARGET) finance_tracker.c $(LIBS)

clean:
	 rm -f $(TARGET)

cleanall:
	 rm -f tracker *.o *.bin *.dat income_*.bin expense_*.bin
	 @echo "All data files and binaries deleted."

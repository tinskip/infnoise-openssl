CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2
LDFLAGS = -shared -lcrypto -linfnoise 
RM = rm -f

TARGET_NAME = infnoise
ifeq ($(OS),Windows_NT)
	TARGET_LIB = $(TARGET_NAME).dll
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		TARGET_LIB = $(TARGET_NAME).so
        else
		ifeq ($(UNAME_S),Darwin)
			TARGET_LIB =$(TARGET_NAME).dylib
			CFLAGS += -I/usr/local/Cellar/libftdi/1.4/include/libftdi1/
		else
			$(error Unknown platform $(UNAME_S))
		endif
	endif
endif

SRCS = e_infnoise.c
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)


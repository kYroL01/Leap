#
#   Decoder - Makefile
#   Copyright (C) 2020 Michele Campus <michelecampus5@gmail.com>
#   Copyright (C) 2020 Giusepe Longo  <giuseppe@glongo.it>
#
#   This file is part of Leap.
#
#   Leap is free software: you can redistribute it and/or modify it under the
#   terms of the GNU General Public License as published by the Free Software
#   Foundation, either version 3 of the License, or (at your option) any later
#   version.
#
#   Leap is distributed in the hope that it will be useful, but WITHOUT ANY
#   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
#   A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along with
#   decoder. If not, see <http://www.gnu.org/licenses/>.

# VARIABLES ---------------------------------

CC         =  gcc
CFLAGS     = -Wall
OPT        = -g -O0
LDFLAGS    = -lpcap
#LDPTHREAD  = -lpthread

# --------------- DEPENDENCIES ---------------

# HEADERS  = include/structures.h include/define.h include/functions.h include/flow.h include/uthash.h
SOURCES    = src/leap.c src/functions.c src/flow.h ## list of protocols
OBJ        = $(SOURCES:.c = .o)
#LIBSSL     = -I/usr/include/openssl -lcrypto
LM         = -lm

# --------------- EXECUTABLE -----------------

leap = $(OBJ)

# --------------- UTILS ----------------------

.PHONY: clean cleanall install uninstall build

clean:
	rm -fr *.o

cleanall: clean
	rm -fr ./leap

install:
	cp ./leap /usr/bin

uninstall:
	rm -f /usr/bin/leap

build : $(OBJ)
	$(CC) $(CFLAGS) $(OPT) $(LDFLAGS) $(LIBSSL) $(LM) $(OBJ) -o leap

%.o : %.c
	$(CC) $(CFLAGS) -c $<

#
#    Makefile
#    Copyright (C) 2010  Pali Rohár <pali.rohar@gmail.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#

CC = gcc
CXX = g++
CFLAGS = -O2 -W -Wall -Wsign-compare -fsigned-char
CXXFLAGS = $(CFLAGS) -Wno-write-strings
WINDRES = windres
LDFLAGS =
GTKFLAGS = $(shell pkg-config --cflags --libs gtk+-2.0)

all: wartool pudconvert wargus

win32: wartool.exe pudconvert.exe wargus.exe

clean:
	rm -f wartool wartool.exe wartool.o pudconvert pudconvert.exe pudconvert.o pudconvert-s.o wargus wargus.exe wargus.rc.o wargus.o xmi2mid.o warextract

xmi2mid.o: xmi2mid.cpp

wartool wartool.exe: xmi2mid.o wartool.o pudconvert.o
	$(CXX) $^ $(LDFLAGS) -lz -lpng -lm -o $@

pudconvert-s.o: pudconvert.c
	$(CC) -c $^ $(CFLAGS) -DSTAND_ALONE -o $@

pudconvert pudconvert.exe: pudconvert-s.o
	$(CC) $^ $(LDFLAGS) -lz -o $@

%.rc.o: %.rc
	$(WINDRES) $^ -O coff -o $@

wargus: wargus.c
	$(CC) $^ $(CFLAGS) $(GTKFLAGS) $(LDFLAGS) -o $@

wargus.exe: wargus.o wargus.rc.o
	$(CC) $^ $(LDFLAGS) -mwindows -o $@

warextract: warextract.c
	$(CC) $^ $(CFLAGS) $(GTKFLAGS) $(LDFLAGS) -o $@

#   Copyright (C) 2015 Piotr Chmielnicki
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA



TOCLEAN=	gensigkeys0/gensigkeys0 \
			gensigkeys0/gensigkeys0.exe \
			sign0/sign0 \
			sign0/sign0.exe \
			verify0/verify0 \
			verify0/verify0.exe
all:
	cd gensigkeys0 && go build gensigkeys0.go
	cd sign0 && go build sign0.go
	cd verify0 && go build verify0.go

clean:
	go clean
	rm -fv $(TOCLEAN)

fclean: clean

re: fclean all

# Linux (and *BSD ?) only
install:
	mkdir -p ~/bin/
	install gensigkeys0/gensigkeys0 \
			sign0/sign0 \
			verify0/verify0 \
			~/bin/

uninstall:
	rm -fv	~/bin/gensigkeys0 \
			~/bin/sign0 \
			~/bin/verify0

full: re install

purge: uninstall clean

fmt:
	go fmt gensigkeys0/gensigkeys0.go
	go fmt sign0/sign0.go
	go fmt verify0/verify0.go

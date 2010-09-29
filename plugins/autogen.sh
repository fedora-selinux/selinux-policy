#!/bin/sh
# Run this to generate all the initial makefiles, etc.

defaultArgs="--prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-maintainer-mode"

progname=setroubleshoot-plugins
root_dir=`pwd`

DIE=0

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to build $progname."
	echo "Download the appropriate package for your distribution,"
	echo "or get the source tarball at http://ftp.gnu.org/pub/gnu/autoconf"
	DIE=1
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have automake installed to build $progname."
	echo "Download the appropriate package for your distribution,"
	echo "or get the source tarball at http://ftp.gnu.org/pub/gnu/automake/"
	DIE=1
}

if test "$DIE" -eq 1; then
	exit 1
fi

if test -z "$*"; then
	echo "I am going to run ./configure with the default arguments:"
	echo ""
	echo $defaultArgs
	echo ""
	echo "If you wish to modify them please specify them on"
	echo "the $0 command line."
fi

intltoolize --copy --force --automake

autoreconf -i -v

./configure $defaultArgs "$@"

echo 
echo "Now type 'make' to build $progname."

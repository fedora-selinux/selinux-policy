AC_INIT([setroubleshoot-plugins], [2.1.59],
        [http://bugzilla.redhat.com/bugzilla/enter_bug.cgi?product=setroubleshoot])
AC_CONFIG_SRCDIR(src/Makefile.am)
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE


# make sure we keep ACLOCAL_FLAGS around for maintainer builds to work
AC_SUBST(ACLOCAL_AMFLAGS, "\${ACLOCAL_FLAGS}")

GETTEXT_PACKAGE=setroubleshoot-plugins
AC_SUBST(GETTEXT_PACKAGE)
AM_GLIB_GNU_GETTEXT
IT_PROG_INTLTOOL
ALL_LINGUAS="\
af	am	ar	as	be	bg	bn_IN	bn	ca	\
cs	cy	da	de	el	en_GB	es	et	eu_ES	\
fa	fi	fr	gl	gu	he	hi	hr	hu	\
hy	id	is	it	ja	ka	kn	ko	ku	\
lo	lt	lv	mk	ml	mr	ms	my	nb	\
nl	nn	nso	or	pa	pl	pt_BR	pt	ro	\
ru	si	sk	sl	sq	sr@latin	sr	sv	\
ta	te	th	tr	uk	ur	vi	zh_CN	zh_TW	\
zu									\
"

AC_PROG_LN_S
AM_PATH_PYTHON

pkgdocdir="\${datadir}/doc/$PACKAGE_NAME-$PACKAGE_VERSION"

AC_ARG_WITH([plugindir], AC_HELP_STRING([--with-plugindir=DIR],
                                        [plugin installation directory]),
            [plugindir="$with_plugindir"],
            [plugindir="\${datadir}/setroubleshoot/plugins"])

AC_SUBST(pkgdocdir)
AC_SUBST(plugindir)

AC_CONFIG_FILES([
Makefile
src/Makefile
po/Makefile.in
])

AC_OUTPUT

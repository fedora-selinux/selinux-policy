@INTLTOOL_DESKTOP_RULE@
SUBDIRS = po src gui doc test

HG = hg
HG_REPOSITORY = ssh://hg.fedoraproject.org//hg/hosted/setroubleshoot

desktopdir = $(datadir)/applications
desktop_in_files = setroubleshoot.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

dbus_sessiondir = $(datadir)/dbus-1/services
dbus_session_DATA = sealert.service

dbus_systemservicedir = $(datadir)/dbus-1/system-services
dbus_systemservice_DATA = \
			org.fedoraproject.Setroubleshootd.service \
			org.fedoraproject.SetroubleshootFixit.service 

dbus_systemdir = $(sysconfdir)/dbus-1/system.d
dbus_system_DATA = \
			org.fedoraproject.Setroubleshootd.conf \
			org.fedoraproject.SetroubleshootFixit.conf

polkit_systemdir = $(datadir)/polkit-1/actions
polkit_system_DATA = \
			org.fedoraproject.setroubleshootfixit.policy

autostartdir = $(sysconfdir)/xdg/autostart
autostart_DATA = sealertauto.desktop

EXTRA_DIST = 				\
	setroubleshoot.logrotate	\
	setroubleshoot.logrotate.in	\
	intltool-extract.in		\
	intltool-merge.in		\
	intltool-update.in		\
	$(desktop_in_files)		\
	$(autostart_DATA)		\
	$(dbus_session_DATA)		\
	$(dbus_systemservice_DATA)	\
	$(dbus_system_DATA)		\
	$(polkit_system_DATA)		\
	$(NULL)

pkgdoc_DATA =		\
	AUTHORS		\
	COPYING		\
	ChangeLog	\
	NEWS		\
	README		\
	TODO		\
	$(NULL)

pkgrun_DATA =

pkgvardata_DATA =

pkglog_DATA =

rpm: dist
	rpmbuild -ta $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

srpm: dist
	rpmbuild --define "_sourcedir `pwd`" --define "_srcrpmdir `pwd`" --define "_specdir `pwd`" -ts @PACKAGE@-@VERSION@.tar.gz

setroubleshoot:
	$(LN_S) src setroubleshoot

setroubleshoot.logrotate: setroubleshoot.logrotate.in Makefile
	sed \
	-e s!\@PACKAGE_NAME\@!$(PACKAGE_NAME)!		\
	-e s!\@daemon_name\@!$(daemon_name)!		\
	-e s!\@pkglogdir\@!$(pkglogdir)!		\
	< $< > $@

VERSION_FILE = configure.ac
TAG_NAME    := $(shell echo $(PACKAGE_NAME)    | sed -e s/\\\./_/g -e s/^[0-9]\\\+//g)
TAG_VERSION := $(shell echo $(PACKAGE_VERSION) | sed s/\\\./_/g)
TAG          = $(TAG_NAME)-$(TAG_VERSION)

.PHONY: tag
tag::
	hg tag $(TAG_OPTS) $(TAG)
	@echo "Tagged with: $(TAG)"
	@echo

hg-push:
	$(HG) push $(HG_REPOSITORY)

DISTCLEANFILES = setroubleshoot.logrotate setroubleshoot
BUILT_SOURCES  = setroubleshoot.logrotate setroubleshoot

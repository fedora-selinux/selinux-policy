SUBDIRS = sesearch default_encoding

PYTHON_FILES =			\
	__init__.py			\
	access_control.py		\
	analyze.py			\
	audit_data.py			\
	avc_audit.py			\
	browser.py			\
	config.py			\
	email_alert.py			\
	email_dialog.py			\
	errcode.py			\
	gui_utils.py			\
	html_util.py			\
	log.py				\
	Plugin.py			\
	rpc.py				\
	rpc_interfaces.py		\
	run_cmd.py			\
	server.py			\
	signature.py			\
	util.py				\
	uuid.py				\
	xml_serialize.py		\
	$(NULL)

bin_SCRIPTS =				\
	sealert				\
	$(NULL)

sedispatch_LDADD = $(CAPNG_LDADD)
sedispatch_SOURCES = 			\
	sedispatch.c			\
	sedbus.c

seapplet_SOURCES = 			\
	sedbus.h			\
	seapplet.c			\
	sedbus.c

bin_PROGRAMS = 				\
	seapplet			\
	$(NULL)

sbin_PROGRAMS = 			\
	sedispatch			\
	$(NULL)

INCLUDES =  $(SEAPPLET_CFLAGS)

LIBS =   $(SEAPPLET_LIBS)  -lauparse -lselinux

sbin_SCRIPTS =				\
	setroubleshootd			\
	$(NULL)

pkglibexec_SCRIPTS =            	\
        $(NULL)

pkgdir = $(datarootdir)/setroubleshoot
pkg_SCRIPTS =			\
	SetroubleshootFixit.py		\
	updater.py			

pkgconfig_DATA =			\
	setroubleshoot.cfg		\
	$(NULL)

setroubleshootdir = $(pyexecdir)/setroubleshoot
setroubleshoot_PYTHON = $(PYTHON_FILES)

audisp_DATA =				\
	sedispatch.conf			\
	$(NULL)

EXTRA_DIST =				\
	$(PYTHON_FILES)			\
	$(pkg_SCRIPTS)			\
	$(sbin_SCRIPTS)			\
	$(bin_SCRIPTS)			\
	$(audisp_DATA)			\
	config.py.in			\
	$(NULL)

config.py: config.py.in Makefile
	sed \
	-e s!\@PACKAGE_NAME\@!$(PACKAGE_NAME)!			\
	-e s!\@PACKAGE_VERSION\@!$(PACKAGE_VERSION)!		\
	-e s!\@daemon_name\@!$(daemon_name)!			\
	-e s!\@pkgdatadir\@!$(pkgdatadir)!			\
	-e s!\@pkglibdir\@!$(pkglibdir)!			\
	-e s!\@pkglibexecdir\@!$(pkglibexecdir)!		\
	-e s!\@pkgguidir\@!$(pkgguidir)!			\
	-e s!\@plugindir\@!$(plugindir)!			\
	-e s!\@pkgvardatadir\@!$(pkgvardatadir)!		\
	-e s!\@pkgrundir\@!$(pkgrundir)!			\
	-e s!\@pkgconfigdir\@!$(pkgconfigdir)!			\
	-e s!\@pkglogdir\@!$(pkglogdir)!			\
	-e s!\@pid_file\@!$(pid_file)!				\
	-e s!\@html_browser_open\@!$(html_browser_open)!	\
	< $< > $@

setroubleshoot.cfg: config.py
	python config.py -d > $@

DISTCLEANFILES = config.py
BUILT_SOURCES  = config.py

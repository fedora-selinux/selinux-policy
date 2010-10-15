SUBDIRS = po src

EXTRA_DIST = 				\
	intltool-extract.in		\
	intltool-merge.in		\
	intltool-update.in		\
	$(NULL)

pkgdoc_DATA =		\
	AUTHORS		\
	COPYING		\
	ChangeLog	\
	README		\
	$(NULL)


rpm: dist
	rpmbuild -ta $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

srpm: dist
	rpmbuild --define "_sourcedir `pwd`" --define "_srcrpmdir `pwd`" --define "_specdir `pwd`" -ts @PACKAGE@-@VERSION@.tar.gz

VERSION_FILE = configure.ac
TAG_NAME    := $(shell echo $(PACKAGE_NAME)    | sed -e s/\\\./_/g -e s/^[0-9]\\\+//g)
TAG_VERSION := $(shell echo $(PACKAGE_VERSION) | sed s/\\\./_/g)
TAG          = $(TAG_NAME)-$(TAG_VERSION)

.PHONY: tag
tag::
	hg tag $(TAG_OPTS) $(TAG)
	@echo "Tagged with: $(TAG)"
	@echo


EXTRA_DIST =				\
	sesearch.c				\
	sesearch_wrapper.c		\
	__init__.py				\
	setup.py				\
	$(NULL)

all-am: python-build

python-build: sesearch.c
	@mkdir -p setroubleshoot/sesearch
	@cp __init__.py setroubleshoot/sesearch
	$(PYTHON) setup.py build

install-exec-hook:
	$(PYTHON) setup.py install `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`

uninstall-hook: 
	$(PYTHON) setup.py uninstall `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`

clean-local:
	$(PYTHON) setup.py clean -a


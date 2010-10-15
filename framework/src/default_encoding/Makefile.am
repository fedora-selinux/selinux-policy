EXTRA_DIST =				\
	default_encoding.c			\
	__init__.py				\
	setup.py				\
	$(NULL)

all-am: python-build

python-build: default_encoding.c
	@mkdir -p setroubleshoot/default_encoding
	@cp __init__.py setroubleshoot
	$(PYTHON) setup.py build

install-exec-hook:
	$(PYTHON) setup.py install `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`

uninstall-hook: 
	$(PYTHON) setup.py uninstall `test -n "$(DESTDIR)" && echo --root $(DESTDIR)`

clean-local:
	$(PYTHON) setup.py clean -a
	rm -f *~

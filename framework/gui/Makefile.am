ICON_FILES = \
	scalable/setroubleshoot_red_icon.svg \
	scalable/setroubleshoot_icon.svg \
	48x48/setroubleshoot_red_icon.png \
	48x48/setroubleshoot_icon.png \
	32x32/setroubleshoot_red_icon.png \
	32x32/setroubleshoot_icon.png \
	24x24/setroubleshoot_red_icon.png \
	24x24/setroubleshoot_icon.png \
	22x22/setroubleshoot_red_icon.png \
	22x22/setroubleshoot_icon.png \
	16x16/setroubleshoot_red_icon.png \
	16x16/setroubleshoot_icon.png 

GUI_FILES =				\
	browser.glade		\
	bug_report.glade	\
	fail_dialog.glade	\
	success_dialog.glade	\
	$(NULL)

icondir = /usr/share/icons/hicolor/

pkggui_DATA = $(GUI_FILES)

EXTRA_DIST =			\
	$(GUI_FILES)		\
	$(ICON_FILES)		\
	$(NULL)

install-data-hook:
	for i in $(ICON_FILES); do d=`dirname $$i`; \
		$(mkdir_p)  $(DESTDIR)$(icondir)$$d/apps;\
		install --mode 644 $$i $(DESTDIR)$(icondir)$$d/apps; done
	$(mkdir_p)  $(DESTDIR)$(datadir)/usr/share/setroubleshoot/gui
	$(LN_S) -f $(icondir)24x24/apps/setroubleshoot_icon.png $(DESTDIR)$(datadir)/setroubleshoot/gui

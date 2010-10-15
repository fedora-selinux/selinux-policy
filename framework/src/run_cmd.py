# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2008 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

__all__ = ["RunCmdGUI",
          ]

import os
import signal
#import sys

def wait_status(status):
    exit_status = (status >> 8) & 0xFF
    signal     = status & 0xFF
    return (exit_status, signal)


import pygtk
pygtk.require("2.0")
import gtk
import gobject

if __name__ == "__main__":
    import gettext
    from setroubleshoot.config import parse_config_setting, get_config
    gettext.install(domain    = get_config('general', 'i18n_text_domain'),
		    localedir = get_config('general', 'i18n_locale_dir'))
    from setroubleshoot.log import log_init
    log_init('test', {'console':True,
             'level':'debug'})

from setroubleshoot.log import *

#------------------------------------------------------------------------

STATE_UNINITIALIZED = 0
STATE_NOT_RUN       = 1
STATE_RUNNING       = 2
STATE_DONE          = 3


TERMIOS_IFLAG, TERMIOS_OFLAG, TERMIOS_CFLAG, TERMIOS_LFLAG, TERMIOS_ISPEED, TERMIOS_OSPEED, TERMIOS_CC = range(7)

#------------------------------------------------------------------------

def set_raw_input(fd):
    import termios
    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)

    new[TERMIOS_IFLAG] = 0
    new[TERMIOS_CFLAG] &= ~termios.CSIZE
    new[TERMIOS_CFLAG] |= (termios.CREAD | termios.CS8)
    new[TERMIOS_LFLAG] &= ~(termios.ECHO | termios.ECHOE | termios.ECHONL | termios.ECHOKE |
			    termios.ECHOPRT | termios.ECHOCTL | termios.ICANON)
    new[TERMIOS_LFLAG] |= termios.ISIG;
    new[TERMIOS_CC][termios.VMIN] = 1;
    new[TERMIOS_CC][termios.VTIME] = 0;

    termios.tcsetattr(fd, termios.TCSADRAIN, new)
    return old

def get_password(prompt=None):
    dlg = PasswordDialog(prompt)
    rc = dlg.run()
    return dlg.get_password()

#------------------------------------------------------------------------

class TextWindow(gtk.Bin):
    '''A widget which displays multiline text, adds scrollbars when necessary and can
    optionally be enclosed in a frame. The widget also implements the following
    visibility behavior:
    * if there is no text the widget hides itself
    * when text is inserted the widget shows itself and scrolls so the most recent
      text is visible.
    '''

    def __init__(self, frame=None, color=None):
	gtk.Bin.__init__(self)
	self.text_buffer = gtk.TextBuffer()
	self.text_view = gtk.TextView(self.text_buffer)
	self.text_view.set_editable(False)
	self.myname = frame

	self.scrolled_window = gtk.ScrolledWindow()
	self.scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	self.scrolled_window.add(self.text_view)

	if frame is None:
	    self.add(self.scrolled_window)
	else:
	    self.frame = gtk.Frame(frame)
	    self.frame.add(self.scrolled_window)
	    self.add(self.frame)

	if color is not None:
	    self.text_view.modify_text(gtk.STATE_NORMAL, gtk.gdk.color_parse(color))

    def clear_text(self):
	self.set_text('')
	self.hide()

    def set_text(self, text):
	self.text_buffer.set_text(text)

    def append_text(self, text):
	end_iter = self.text_buffer.get_end_iter()
	self.text_buffer.insert(end_iter, text)
	self.text_view.scroll_to_mark(self.text_buffer.get_insert(), 0)
	self.show()


    def do_size_allocate(self, allocation):
        if debug:
            log_gui.debug("%s.do_size_allocate: (%d,%d)(%dx%d)",
                          self.__class__.__name__, allocation.x, allocation.y, allocation.width, allocation.height)

        self.child.size_allocate(allocation)

    def show(self):
	gtk.Bin.show(self)
	self.child.show_all()

    def hide(self):
	gtk.Bin.hide(self)
	self.child.hide_all()

    def do_size_request(self, requisition):
        if debug:
            log_gui.debug("%s.do_size_request: %s (%dx%d)",
                          self.__class__.__name__, self.myname, requisition.width, requisition.height)

	child_req = gtk.gdk.Rectangle(0, 0, *self.child.size_request())

	requisition.width = child_req.width
	requisition.height = child_req.height

gobject.type_register(TextWindow)

#------------------------------------------------------------------------

class TTYView(gtk.Bin):
    '''A widget which displays output from a TTY and accepts input for the TTY
    in a single line text entry box. The widget also filters TTY output looking
    for special strings such as 'password:'. The widget remains hidden as long
    as there is no output to display. Special strings (e.g. password) are
    intercepted and are not inserted into the output buffer but instead trigger
    a password prompt dialog.
    '''

    def __init__(self, ttyout_fd, parent_dialog, frame=None):
	gtk.Bin.__init__(self)
	self.ttyout_fd = ttyout_fd
	self.parent_dialog = parent_dialog

	self.ttyout_view = TextWindow()

        self.ttyin = gtk.Entry()
	self.ttyin.set_text('')
	self.ttyin.connect('activate', self.on_ttyin_activate)

	hbox = gtk.HBox()
	hbox.pack_start(gtk.Label(_("Input: ")), False, False)
	hbox.pack_start(self.ttyin, True, True)

	self.vbox = gtk.VBox()
	self.vbox.pack_start(self.ttyout_view, True, True, 0)
	self.vbox.pack_start(hbox, False, False, 0)
	
	if frame is None:
	    self.add(self.vbox)
	else:
	    self.frame = gtk.Frame(frame)
	    self.frame.add(self.vbox)
	    self.add(self.frame)

    def set_fd(self, fd):
	self.ttyout_fd = fd

    def show(self):
	gtk.Bin.show(self)
	self.child.show_all()
        self.ttyin.grab_focus()

    def hide(self):
	gtk.Bin.hide(self)
	self.child.hide_all()

    def clear_text(self):
	self.ttyout_view.clear_text()
	self.hide()

    def append_text(self, text):
        import re
	if re.search('password:', text, re.IGNORECASE):
	    dlg = PasswordDialog(text)
	    rc = dlg.run()
	    if rc != gtk.RESPONSE_OK:
		self.parent_dialog.response(rc)
		return
	    password = dlg.get_password()		
	    password += '\n'
	    while password != '':
		n = os.write(self.ttyout_fd, password)
		password = password[n:]
	    return

	if re.search('\S', text):
	    self.ttyout_view.append_text(text)
	    self.show()

    def on_ttyin_activate(self, widget, data=None):
	text = self.ttyin.get_text() + '\n'
	while text != '':
	    n = os.write(self.ttyout_fd, text)
	    text = text[n:]
	self.ttyin.set_text('')
	self.hide()

    def do_size_allocate(self, allocation):
        if debug:
            log_gui.debug("%s.do_size_allocate: (%d,%d)(%dx%d)",
                          self.__class__.__name__, allocation.x, allocation.y, allocation.width, allocation.height)

        self.child.size_allocate(allocation)

    def do_size_request(self, requisition):
        if debug:
            log_gui.debug("%s.do_size_request: (%dx%d)",
                          self.__class__.__name__, requisition.width, requisition.height)

	child_req = gtk.gdk.Rectangle(0, 0, *self.child.size_request())

	requisition.width = child_req.width
	requisition.height = child_req.height

gobject.type_register(TTYView)

#------------------------------------------------------------------------

class PasswordDialog:
    '''Prompt for a password, input is echoed with non-text. If prompt is None
    it will default to 'Password:'
    '''

    def __init__(self, prompt=None, title=None, parent=None):
	self.password = None

	if title is None:
	    self.title = _("Enter Password")
	else:
	    self.title = title

	self.dlg = gtk.Dialog(self.title, parent, 0, (gtk.STOCK_OK, gtk.RESPONSE_OK, gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
	self.dlg.set_position(gtk.WIN_POS_CENTER)
        self.entry = gtk.Entry()
	self.entry.set_visibility(False)
	self.entry.connect('activate', self.on_password_activate)

	if prompt is not None:
	    label = gtk.Label(prompt)
	else:
	    label = gtk.Label(_("Password: "))

	hbox = gtk.HBox()
	hbox.pack_start(label, False, False, 0)
	hbox.pack_start(self.entry, False, False, 0)
	self.dlg.vbox.pack_start(hbox, False, False, 0)
	self.dlg.show_all()

    def on_password_activate(self, widget, data=None):
	'Make <Enter> dismiss the dialog'
	self.dlg.response(gtk.RESPONSE_OK)

    def get_password(self):
	return self.password
    
    def run(self):
	response = self.dlg.run()
	if response == gtk.RESPONSE_OK:
	    self.password = self.entry.get_text()
	self.dlg.destroy()
	return response
	
#------------------------------------------------------------------------

class IO_Watch:
    '''Asynchronously listen for IO on a file descriptor. When it arrives
    dispatch it via insert_text callback.
    '''
    
    def __init__(self, name, fd, insert_text):
	self.name = name
	self.fd = fd
	self.insert_text = insert_text
	self.io_id = gobject.io_add_watch(fd, gobject.IO_IN|gobject.IO_HUP|gobject.IO_ERR, self.on_io_read)	
    
    def drain_and_close(self):
	while True and self.name != 'ttyout':
	    data = os.read(self.fd, 1024)
	    if data == '':
		break
	    else:
		self.insert_text(self.name, data)

	os.close(self.fd)
	gobject.source_remove(self.io_id)
	    

    def on_io_read(self, fd, condition):
        if condition & gobject.IO_IN:
	    try:
		data = os.read(fd, 1024)
		if data == '':
		    return False
	    except OSError, e:
                import errno
		if e.errno == errno.EINTR:
		    return True
	    else:
		if data:
		    self.insert_text(self.name, data)
        if condition & gobject.IO_HUP:
            return False
        else:
            return True

#------------------------------------------------------------------------

class RunCmdGUI(object):

    '''A dialog which can asynchronously execute a command as a
    subprocess, present the stdout and stderr, if any, to the user in
    independent text windows updating the text as the subprocess runs,
    abort the subprocess during its execution, and display to the user
    the exit status of the subprocess. The stderr text is displayed in
    red. The subprocess is also provided with a pseudo-terminal (pty)
    so that if it chooses to open /dev/tty for console interaction
    that data stream is also captured and presented to the user. This
    means the dialog actually manages 3 independent data streams from
    the subprocess, stdout, stderr, and tty. Each of these data
    streams are presented in individual text widgets which by default
    are initially hidden in the dialog. The text widget for the data
    steam presents itself in the dialog only when there is text to
    display, this keeps the interface leaner and cleaner. The tty
    stream has special logic to detect password prompts. If a password
    prompt arrives it is handled by a password dialog, otherwise a TTY
    widget opens with the TTY output and an input box.'''

    def __init__(self, cmd="", parent=None):
        self.cmd = cmd
        self.pid = None

	self.stdin_fd = None
	self.stdout_fd = None
	self.stderr_fd = None
	self.tty_master_fd = None
	self.tty_slave_fd = None

        self.exit_status = 0
        self.exit_signal = 0
        self.title = _("SELinux Fix")
	self.state = STATE_UNINITIALIZED
	self.status_msg = ''

	self.dlg = gtk.Dialog(self.title, parent, 0, (gtk.STOCK_OK, gtk.RESPONSE_OK, gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
	self.dlg.set_position(gtk.WIN_POS_CENTER)
	self.dlg.connect('response', self.on_response)

        self.cmd_widget = gtk.Entry()
	self.cmd_widget.set_text(self.cmd)
	self.cmd_widget.connect('activate', self.on_cmd_activate)
	self.cmd_frame = gtk.Frame(_("Command"))
	self.cmd_frame.add(self.cmd_widget)

	self.stdout_view = TextWindow('stdout')
	self.stderr_view = TextWindow('stderr', 'red')

	self.tty_view = TTYView(None, self.dlg, 'tty')

	self.button_box = gtk.HBox()

	self.run_button = gtk.Button(label=_("Run Command"))
	self.run_button.connect('clicked', self.on_run)

	self.stop_button = gtk.Button(label=_("Stop Command"))
	self.stop_button.connect('clicked', self.on_cancel)

	self.button_box.pack_start(self.run_button, False, False, 0)
	self.button_box.pack_start(self.stop_button, False, False, 0)

	self.status_box = gtk.HBox()
        self.status_widget = gtk.Entry()
	self.status_widget.set_property('editable', False)

        self.progress = gtk.ProgressBar()
	self.progress.set_pulse_step(0.05)

	self.status_box.pack_start(self.status_widget, True, True, 0)
	self.status_box.pack_start(self.progress, False, False, 0)
	self.status_frame = gtk.Frame(_("Status"))
	self.status_frame.add(self.status_box)


	warning_msg = gtk.Label()
	warning_msg.set_use_markup(True)
	warning_msg.set_markup('<span foreground="red">'+
			       _("Warning: You are responsible for verifying this command is correct")+
			       '</span>')

	warning_msg.show()
	self.cmd_frame.show_all()
	self.stdout_view.hide()
	self.stderr_view.hide()
	self.tty_view.hide()
	self.button_box.show_all()
	self.status_frame.show_all()

	self.dlg.vbox.pack_start(warning_msg, False, False, 0)
	self.dlg.vbox.pack_start(self.cmd_frame, False, False, 0)
	self.dlg.vbox.pack_start(self.stdout_view, True, True, 0)
	self.dlg.vbox.pack_start(self.stderr_view, True, True, 0)
	self.dlg.vbox.pack_start(self.tty_view, True, True, 0)
	self.dlg.vbox.pack_start(self.button_box, False, False, 0)
	self.dlg.vbox.pack_start(self.status_frame, False, False, 0)

        self.set_state(STATE_NOT_RUN)

    def on_response(self, dialog, response):
	if response == gtk.RESPONSE_CANCEL:
	    self.stop_cmd()

    def on_cancel(self, widget, data=None):
	self.stop_cmd()

    def stop_cmd(self):
        if self.pid:
            os.kill(self.pid, signal.SIGKILL)

    def progress_pulse(self):
	if self.pid is None: return False
	self.progress.pulse()
	return True

    def set_state(self, state):
	if self.state == state: return
        self.state = state

        if self.state == STATE_NOT_RUN:
            self.status_msg = _("Not Run Yet")
	    self.cmd_widget.set_property('editable', True)
            self.run_button.set_sensitive(True)
            self.stop_button.set_sensitive(False)
	    self.stdout_view.clear_text()
	    self.stderr_view.clear_text()
	    self.tty_view.clear_text()
	    self.progress.hide()
            self.dlg.set_response_sensitive(gtk.RESPONSE_OK, False)
            self.dlg.set_response_sensitive(gtk.RESPONSE_CANCEL, True)
        elif self.state == STATE_RUNNING:
            self.status_msg = _("Running...")
            self.dlg.set_title("Run: " + self.title)
	    self.cmd_widget.set_property('editable', False)
            self.run_button.set_sensitive(False)
            self.stop_button.set_sensitive(True)
	    self.stdout_view.clear_text()
	    self.stderr_view.clear_text()
	    self.tty_view.clear_text()
	    self.stderr_view.hide()
	    self.progress.show()
            self.dlg.set_response_sensitive(gtk.RESPONSE_OK, False)
            self.dlg.set_response_sensitive(gtk.RESPONSE_CANCEL, False)
	    gobject.timeout_add(100, self.progress_pulse)
        elif self.state == STATE_DONE:
            if self.exit_signal != 0:
                self.status_msg = _("Interrupted, exit on signal %d") % self.exit_signal
            elif self.exit_status == 0:
                self.status_msg = _("Success")
            else:
                self.status_msg = _("Failed, exit status = %d") % self.exit_status

            self.dlg.set_title(_("Done: ") + self.title)
	    self.cmd_widget.set_property('editable', True)
            self.run_button.set_sensitive(True)
            self.stop_button.set_sensitive(False)
            self.dlg.set_response_sensitive(gtk.RESPONSE_OK, True)
            self.dlg.set_response_sensitive(gtk.RESPONSE_CANCEL, False)
	    self.progress.set_fraction(0)
	    self.progress.hide()
        else:
            raise ValueError("unknown run state = %s" % self.state)
        
        self.status_widget.set_text(self.status_msg)

    def insert_text(self, buf, text):
	if debug:
	    log_subprocess.debug("insert_text: buf=%s text=%s", buf, text)
	if buf == 'stdout':
	    text_view = self.stdout_view
	elif buf == 'stderr':
	    text_view = self.stderr_view
	elif buf == 'ttyout':
	    text_view = self.tty_view
	else:
	    raise ValueError("insert_text() unknown buffer (%s)" % buf)
	    
	text_view.append_text(text)

    def on_cmd_activate(self, widget, data=None):
        self.run_cmd()

    def on_run(self, widget, data=None):
        self.run_cmd()

    def on_child_exit(self, pid, condition):
	self.pid = None
	self.exit_status, self.exit_signal = wait_status(condition)

	self.stdout_io.drain_and_close()
	self.stderr_io.drain_and_close()
	self.ttyout_io.drain_and_close()

        self.set_state(STATE_DONE)

    def run_cmd(self):
        def child_setup():
            os.setsid()
            tty_slave_fd = os.open(self.tty_slave_name, os.O_RDWR)
            os.close(tty_slave_fd)
            os.close(self.tty_master_fd)


	self.set_state(STATE_RUNNING)
        self.cmd = self.cmd_widget.get_text()

        self.tty_master_fd, self.tty_slave_fd = os.openpty()
        self.tty_slave_name = os.ttyname(self.tty_slave_fd)

	self.tty_view.set_fd(self.tty_master_fd)
        set_raw_input(self.tty_master_fd)

	try:
            import shlex
	    self.pid, self.stdin_fd, self.stdout_fd, self.stderr_fd = \
		      gobject.spawn_async(shlex.split(self.cmd),
					  standard_output=True, standard_error=True,
					  flags=gobject.SPAWN_DO_NOT_REAP_CHILD | gobject.SPAWN_SEARCH_PATH,
                                          child_setup=child_setup)
	except Exception, e:
	    self.insert_text('stderr', str(e))
	    self.exit_status = -1
	    self.set_state(STATE_DONE)
	    return

        gobject.child_watch_add(self.pid, self.on_child_exit)
        self.stdout_io = IO_Watch('stdout', self.stdout_fd, self.insert_text)
        self.stderr_io = IO_Watch('stderr', self.stderr_fd, self.insert_text)
        self.ttyout_io = IO_Watch('ttyout', self.tty_master_fd, self.insert_text)

    def set_cmd(self, cmd=None):
        if cmd is not None:
            self.cmd = cmd
        self.cmd_widget.set_text(self.cmd)
	self.stdout_view.clear_text()
	self.stderr_view.clear_text()

        self.set_state(STATE_NOT_RUN)





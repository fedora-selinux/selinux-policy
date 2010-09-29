# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2006,2007,2008 Red Hat, Inc.
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

# Needed to silence warnings if X display is not present
import warnings
warnings.filterwarnings('ignore', 'could not open display')

import pygtk
pygtk.require("2.0")
import gtk
#import gtkhtml2
#import pynotify
import gobject 
#import gnome
#import os
#import datetime
import re
#import selinux

from setroubleshoot.config import get_config
from setroubleshoot.errcode import *
from setroubleshoot.signature import *
from setroubleshoot.util import *
from setroubleshoot.log import *

#------------------------------------------------------------------------------

__all__ = ['map_column_types',
           'FileChooserDialog',
           'get_display',
           'display_help',
           'display_verify',
           'display_error',
           'display_traceback',
	   'visibility_state_to_string',
           'window_state_to_string',
           'parse_window_state',
          ]


#------------------------------------------------------------------------------

map_column_types = {
    'icon'     : gtk.gdk.Pixbuf,
    'string'   : gobject.TYPE_STRING,
    'int'      : gobject.TYPE_INT,
    'pyobject' : gobject.TYPE_PYOBJECT,
    'toggle'   : gobject.TYPE_BOOLEAN
    }

#------------------------------------------------------------------------------

def get_display():
    try:
        dpy = gtk.gdk.Display('')
        dpy_name = dpy.get_name()
        return dpy_name
    except RuntimeError, e:
        return None

    # --- Interaction Dialogs ---

def display_help(message, title=_("Help"), parent=None):
    if get_display() is None:
        return None

    dlg = gtk.Dialog(title, parent, 0, (gtk.STOCK_OK, gtk.RESPONSE_OK))
    dlg.set_position(gtk.WIN_POS_MOUSE)
    dlg.set_default_size(400, 300)

    text_buffer = gtk.TextBuffer()
    text_buffer.set_text(message)

    text_view = gtk.TextView(text_buffer)
    text_view.set_editable(False)

    scrolled_window = gtk.ScrolledWindow()
    scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    scrolled_window.add(text_view)

    dlg.vbox.pack_start(scrolled_window, True, True, 0)

    dlg.show_all()
    rc = dlg.run()
    dlg.destroy()
    return True

    
def display_verify(message):
    if get_display() is None:
        return None
    dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_INFO, gtk.BUTTONS_YES_NO, message)
    dlg.set_position(gtk.WIN_POS_MOUSE)
    dlg.show_all()
    rc = dlg.run()
    dlg.destroy()
    if rc == gtk.RESPONSE_YES:
        return True
    if rc == gtk.RESPONSE_NO:
        return False
    return None
    
def display_error(message):
    if get_display() is None:
        return None
    dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, message)
    dlg.set_position(gtk.WIN_POS_CENTER)
    dlg.show_all()
    rc = dlg.run()
    dlg.destroy()
    if rc == gtk.RESPONSE_OK:
        return True
    return None


def display_traceback(who,  parent=None):
    if get_display() is None:
        return None

    import traceback

    stacktrace = traceback.format_exc()
    message = _("Opps, %s hit an error!" % who)

    title= who + ' ' + _("Error")
    dlg = gtk.Dialog(title, parent, 0, (gtk.STOCK_OK, gtk.RESPONSE_OK))
    dlg.set_position(gtk.WIN_POS_CENTER)
    dlg.set_default_size(600, 400)

    text_buffer = gtk.TextBuffer()
    text_buffer.set_text(message+'\n\n'+stacktrace)

    text_view = gtk.TextView(text_buffer)
    text_view.set_editable(False)

    scrolled_window = gtk.ScrolledWindow()
    scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    scrolled_window.add(text_view)

    dlg.vbox.pack_start(scrolled_window, True, True, 0)

    dlg.show_all()
    rc = dlg.run()
    dlg.destroy()
    if rc == gtk.RESPONSE_OK:
        return True
    return None

def visibility_state_to_string(state):
    
    if state == gtk.gdk.VISIBILITY_UNOBSCURED:     return "fully_visible"
    if state == gtk.gdk.VISIBILITY_PARTIAL:        return "partially_visible"
    if state == gtk.gdk.VISIBILITY_FULLY_OBSCURED: return "not_visible"
    return "unknown state (%s)" % state

def window_state_to_string(state):
    flags = []
    if state & gtk.gdk.WINDOW_STATE_WITHDRAWN:
        flags.append('hidden')
    if state & gtk.gdk.WINDOW_STATE_ICONIFIED:
        flags.append('iconified')
    if state & gtk.gdk.WINDOW_STATE_MAXIMIZED:
        flags.append('maximized')
    if state & gtk.gdk.WINDOW_STATE_STICKY:
        flags.append('sticky')
    if state & gtk.gdk.WINDOW_STATE_FULLSCREEN:
        flags.append('fullscreen')
    if state & gtk.gdk.WINDOW_STATE_ABOVE:
        flags.append('above')
    if state & gtk.gdk.WINDOW_STATE_BELOW:
        flags.append('below')
    return ','.join(flags)

def parse_window_state(str):
    state = 0

    str = re.sub('[,;: \t]+', ',', str)
    flags = str.lower().split(',')
    for flag in flags:
        if not flag: continue
        if flag == 'hidden':
            state |= gtk.gdk.WINDOW_STATE_WITHDRAWN
        elif flag == 'iconified':
            state |= gtk.gdk.WINDOW_STATE_ICONIFIED
        elif flag == 'maximized':
            state |= gtk.gdk.WINDOW_STATE_MAXIMIZED
        elif flag == 'sticky':
            state |= gtk.gdk.WINDOW_STATE_STICKY
        elif flag == 'fullscreen':
            state |= gtk.gdk.WINDOW_STATE_FULLSCREEN
        elif flag == 'above':
            state |= gtk.gdk.WINDOW_STATE_ABOVE
        elif flag == 'below':
            state |= gtk.gdk.WINDOW_STATE_BELOW
        else:
            print "WARNING: unknown window state = '%s'" % (flag)
        
    return state
        
#------------------------------------------------------------------------------
class FileChooserDialog:
    def __init__(self):
        pass
    
    def get_filename(self, title):
	result = None
	file_open = gtk.FileChooserDialog(title, action=gtk.FILE_CHOOSER_ACTION_OPEN,
            buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL, gtk.STOCK_OPEN, gtk.RESPONSE_OK))

	if file_open.run() == gtk.RESPONSE_OK:
		result = file_open.get_filename()
	file_open.destroy()
        return result
        
#------------------------------------------------------------------------------

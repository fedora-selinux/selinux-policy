#!/usr/bin/env python
# Author: Thomas Liu <tliu@redhat.com>
# Author: Dan Walsh <dwalsh@redhat.com>
# Copyright (C) 2006-2010 Red Hat, Inc.
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

import gettext
from subprocess import *
import random
from gettext import ngettext as P_
import sys, os
from xml.dom import minidom
import datetime
import time
import gtkhtml2
import xmlrpclib
import pygtk
import gobject
import gnomekeyring
import gtk
import gtk.glade
from setroubleshoot.log import *
from setroubleshoot.analyze import *
from setroubleshoot.config import get_config
from setroubleshoot.email_dialog import *
from setroubleshoot.errcode import *
from setroubleshoot.signature import *
from setroubleshoot.util import *
from setroubleshoot.html_util import *
from setroubleshoot.rpc import *
from setroubleshoot.rpc_interfaces import *
from setroubleshoot.run_cmd import *
import re
import dbus
import slip.dbus.service
from slip.dbus import polkit
import tempfile
import report
import report.io
import report.io.GTKIO
import report.accountmanager

GLADE_DIRECTORY = "/usr/share/setroubleshoot/gui/"
PREF_DIRECTORY = os.environ['HOME'] + "/"
PREF_FILENAME = ".setroubleshoot"
PREF_PATH = PREF_DIRECTORY + PREF_FILENAME
UPDATE_PROGRAM = "/usr/bin/gpk-update-viewer"

package_list = set()
# The main security alert window
import syslog
class BrowserApplet:
    """Security Alert Browser"""

    def on_troubleshoot_button_clicked(self, widget):
        if self.troubleshoot_visible:
            self.solutions_pane.hide()
            self.troubleshoot_visible = False
        else:
            self.solutions_pane.show()
            self.troubleshoot_visible = True
            self.window.set_size_request(900, 630)

    def empty_load(self):
        self.clear_rows()
        self.alert_count_label.set_label("No alerts.")
        self.date_label.set_label("")
        self.start_label.set_label("")

    def __init__(self, username=None, server=None, list=False, domain=None):
        self.RECT_SIZE = 30
        builder = gtk.Builder()
        builder.add_from_file("/usr/share/setroubleshoot/gui/browser.glade") 
        self.plugins = load_plugins()

        self.alert_list = []
        server.connect('signatures_updated', self.update_alerts)
        self.pane = builder.get_object("solutions_pane")
        self.table = builder.get_object("solutions_table")
        self.window = builder.get_object("main_window")
        self.window.connect("destroy", self.quit)
       
        self.source_label = builder.get_object("source_label")
        self.target_label = builder.get_object("target_label")
        self.class_label = builder.get_object("class_label")
        self.access_label = builder.get_object("access_label")
        self.access_title_label = builder.get_object("access_title_label")
        self.severity_label = builder.get_object("severity_label")
        self.likelihood_label = builder.get_object("likelihood_label")
        self.if_label = builder.get_object("if_label")
        self.then_label = builder.get_object("then_label")
        self.do_label = builder.get_object("do_label")
        self.alert_count_label = builder.get_object("alert_count_label")
        self.date_label = builder.get_object("date_label")
        self.start_label = builder.get_object("start_label")
        self.first_label = builder.get_object("first_label")
        self.latest_label = builder.get_object("latest_label")
        self.occurance_label = builder.get_object("occurance_label")
        self.current_policy_label = builder.get_object("current_policy_label")
        self.newer_policy_label = builder.get_object("newer_policy_label")
        self.troubleshoot_checkbutton = builder.get_object("troubleshoot_checkbutton")

        self.next_button = builder.get_object("next_button")
        self.previous_button = builder.get_object("previous_button")
        self.report_button = builder.get_object("report_button")
        self.ignore_button = builder.get_object("ignore_button")
        self.delete_button = builder.get_object("delete_button")
        self.grant_button = builder.get_object("grant_button")
        self.alert_list_window = builder.get_object("alert_list_window") 
        self.alert_list_window.connect("delete-event", self.close_alert_window)
        self.list_all_button = builder.get_object("list_all_button")
        self.treeview_window = builder.get_object("treeview_window") 

        self.solutions_pane = builder.get_object("solutions_pane")
        self.solutions_pane.hide()

        self.solutions_vbox = builder.get_object("solutions_vbox")
        self.bug_report_window = None

        builder.connect_signals(self)       
        self.username = username
        self.database = server
        self.server = server
        self.domain = domain
        self.window.show()
        self.alert_list_window.hide()
        self.empty_load()
        self.load_data()
        self.liststore = gtk.ListStore(int, str, str, str, str, str) 
        self.make_treeview()
        self.updaterpipe = Popen(["/usr/bin/python", "/usr/share/setroubleshoot/updater.py"], stdout=PIPE)
        gobject.timeout_add(1000, self.read_pipe().next)
        self.troubleshoot_visible=False
        if self.troubleshoot_checkbutton.get_active():
            self.on_troubleshoot_button_clicked(None)
        self.current_alert = -1
        self.accounts = report.accountmanager.AccountManager()

    def read_pipe(self):
        while True:
            if not self.updaterpipe.poll() is None:
                break
            yield True
        if self.updaterpipe.returncode:
            self.current_policy_label.set_text(_("Error while checking policy version."))
        else:
            while True:
                line = self.updaterpipe.stdout.readline()            
                if "newer" in line:
                    self.report_button.set_tooltip_text(_("There is a newer version of policy available.  Updating your policy may fix the denial that you having problems with."))
                    self.newer_policy_label.set_text("%s: %s" % (_("Newest Version"), line.split(" ")[1])) 
                    if os.access(UPDATE_PROGRAM, os.X_OK):
                        self.report_button.set_label(_("Update Policy"))
                elif "current" in line:
                    self.current_policy_label.set_text("%s" % (line.split(" ")[1]))
                elif "error" in line or "done" in line:
                    break
        yield False
 
    def install_button_clicked(self, widget):
        if not os.access(UPDATE_PROGRAM, os.X_OK):
            return

        if os.fork() == 0:
            os.execv(UPDATE_PROGRAM, [])

    def make_treeview(self):
        tmsort = gtk.TreeModelSort(self.liststore)
       
        cols = [_("#"), _("Source"), _("Target"), _("Class"), _("Access"), _("Last Seen")]
        self.treeview = gtk.TreeView(tmsort)
        x = 0
        for c in cols:
            cell = gtk.CellRendererText()
            col = gtk.TreeViewColumn(c)
            col.pack_start(cell, True)
            col.set_attributes(cell, text=x)
            col.set_sort_column_id(x)
            col.set_resizable(True)
            self.treeview.append_column(col)
            x +=1 
        self.treeview.set_headers_clickable(True)
        self.treeview_window.add(self.treeview)
        self.treeview.connect("row-activated", self.row_activated)
    
    def row_activated(self, x, y, z):
        store, iter = x.get_selection().get_selected()
        if iter == None:
            return
        self.current_alert = store.get_value(iter, 0) - 1
        self.alert_list_window.hide()
        self.show_current_alert()

    def update_alerts(self, database, type, item):
        def new_siginfo_callback(sigs):
            for siginfo in sigs.signature_list:
                self.alert_list.append(siginfo)
            self.show_current_alert()

        if type == "add" or type == "modify": 
            async_rpc = self.database.query_alerts(item)
            async_rpc.add_callback(new_siginfo_callback)
   

    def show_date(self, alert):
        from setroubleshoot.util import TimeStamp
        # Format the data that we get and display it in the appropriate places
        date_format = "%a %b %e, %Y %r %Z"
        alert_date = alert.last_seen_date
        start_date = alert.first_seen_date
        self.date_label.set_label(alert_date.format(date_format))
        self.start_label.set_label(start_date.format(date_format))
        start_label_text = P_("Alert occurred %d time", "Alert occurred %d times", alert.report_count) % (alert.report_count)
        self.occurance_label.set_label(start_label_text)

    def on_troubleshoot_checkbutton_toggled(self, widget):
        if widget.get_active():
            print "On"
        else:
            print "Off"
            
    def on_ignore_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list):
            sig = self.alert_list[self.current_alert]
            curr_id = sig.local_id

    def load_data(self):
        if self.database is not None:
            criteria = "*"
            async_rpc = self.database.query_alerts(criteria)
            async_rpc.add_callback(self.first_load)
            async_rpc.add_errback(self.database_error)

    def first_load(self, sigs):
        for sig in sigs.siginfos():
            self.alert_list.append(sig)

        if self.current_alert < 0:
            self.current_alert = len(self.alert_list) -1

        self.show_current_alert()
    
    # TODO        
    def database_error(self, method, errno, strerror):
        pass



    def clear_rows(self):
        for child in self.table.get_children():
            self.table.remove(child)
        cols = int(self.table.get_property("n-columns"))
        self.table.resize(1, cols)
        label = gtk.Label()
        label.set_markup("<b>%s</b>" % _("Severity"))
        label.show()
        self.table.attach(label, 0, 1, 0, 1, xoptions=0, yoptions=0)
        label = gtk.Label()
        label.set_markup("<b>%s</b>" % _("Probability"))
        label.show()
        self.table.attach(label, 1, 2, 0, 1, xoptions=0, yoptions=0)

        label = gtk.Label()
        label.set_markup("<b>%s</b>" % _("If"))
        label.show()
        self.table.attach(label, 2, 3, 0, 1, yoptions=0)

        label = gtk.Label()
        label.set_markup("<b>%s</b>" % _("Then"))
        label.show()
        self.table.attach(label, 3, 4, 0, 1, yoptions=0)

        label = gtk.Label()
        label.set_markup("<b>%s</b>" % _("Do"))
        label.show()
        self.table.attach(label, 4, 5, 0, 1, yoptions=0)

    def add_row(self, plugin, sig, args, likelihood):
        avc = sig.audit_event.records
        if_text = sig.substitute(plugin.get_if_text(avc, args))
        then_text = sig.substitute(plugin.get_then_text(avc, args))
        do_text = sig.substitute(plugin.get_do_text(avc, args))

        if not if_text:
            return
        sev_label = gtk.Image()
        pixmap = gtk.gdk.Pixmap(None, self.RECT_SIZE, self.RECT_SIZE, 24)
        cr = pixmap.cairo_create()
        bg_color = sev_label.get_style().bg[0]
        cr.set_source_color(bg_color)
        cr.paint()
        cr.set_source_rgb(0, 0, 0)
        cr.rectangle(0, 0, self.RECT_SIZE, self.RECT_SIZE)
        cr.fill()
        if plugin.level == "red":
            cr.set_source_rgb(1, 0 ,0)
        elif plugin.level == "yellow":
            cr.set_source_rgb(1, 1 ,0)
        elif plugin.level == "green":
            cr.set_source_rgb(0, 1 ,0)
        cr.rectangle(2, 2, self.RECT_SIZE - 4, self.RECT_SIZE - 4)
        cr.fill()
        sev_label.set_from_pixmap(pixmap, None)
        
        like_label = gtk.Image()
        pixmap = gtk.gdk.Pixmap(None, self.RECT_SIZE, self.RECT_SIZE, 24)
        cr = pixmap.cairo_create()
        bg_color = like_label.get_style().bg[0]
        cr.set_source_color(bg_color)
        cr.paint()
        cr.set_source_rgb(0, 0, 0)
        cr.rectangle(0, 0, self.RECT_SIZE, self.RECT_SIZE)
        cr.fill()
        cr.set_source_rgb(237/255., 236/255., 235/255.)
        cr.rectangle(2, 2, self.RECT_SIZE - 4, self.RECT_SIZE - 4)
        cr.fill()

        cr.set_source_rgb(0.3, 0.5, 1)
        total = int((self.RECT_SIZE - 4) * (likelihood / 100.))
        cr.rectangle(2, 2 + self.RECT_SIZE - 4 - total, self.RECT_SIZE - 4, total) 
        cr.fill()

        like_label.set_from_pixmap(pixmap, None)

        if_scroll = gtk.ScrolledWindow()
        if_scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        then_scroll = gtk.ScrolledWindow()
        then_scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        do_scroll = gtk.ScrolledWindow()
        do_scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        if_label = gtk.Label()
        if_scroll.add_with_viewport(if_label)
        if_label.set_text(if_text)
        then_label = gtk.Label()
        then_scroll.add_with_viewport(then_label)
        then_label.set_text(then_text)
        do_label = gtk.Label()
        do_scroll.add_with_viewport(do_label)
        do_label.set_text(do_text)
        then_label.set_alignment(0.0, 0.0)
        if_label.set_alignment(0.0, 0.0)
        do_label.set_alignment(0.0, 0.0)
#        if_label.set_width_chars(25)
        if_label.set_justify(gtk.JUSTIFY_LEFT)
#        then_label.set_width_chars(25)
        then_label.set_justify(gtk.JUSTIFY_LEFT)
#        do_label.set_width_chars(25)
        do_label.set_justify(gtk.JUSTIFY_LEFT)
        then_label.set_padding(10, 10)
        if_label.set_padding(10, 10)
        do_label.set_padding(10, 10)
        sev_label.show()
        like_label.show()
        if_scroll.show()
        if_label.show()
        then_scroll.show()
        then_label.show()
        do_scroll.show()
        do_label.show()

        sev_frame = gtk.Frame()

        sev_frame.set_shadow_type(gtk.SHADOW_NONE)
        sev_frame.show()
        sev_frame.add(sev_label)

        like_frame = gtk.Frame()
        like_frame.set_shadow_type(gtk.SHADOW_NONE)
        like_frame.show()
        like_frame.add(like_label)

        if_frame = gtk.Frame()
        if_frame.set_shadow_type(gtk.SHADOW_OUT)
        if_frame.show()
        if_frame.add(if_scroll)
        if_frame.set_size_request(220, 90)

        then_frame = gtk.Frame()
        then_frame.set_shadow_type(gtk.SHADOW_OUT)
        then_frame.show()
        then_frame.add(then_scroll)
        then_frame.set_size_request(220, 90)

        do_frame = gtk.Frame()
        do_frame.set_shadow_type(gtk.SHADOW_OUT)
        do_frame.show()
        box = gtk.HBox()
        do_frame.add(box)
        do_frame.set_size_request(220, 90)

        box.pack_start(do_scroll)
        #do_button = gtk.Button(label = "Show\nme how")
        #box.pack_end(do_button)

        box.show()
        #do_button.show()

        rows = int(self.table.get_property("n-rows"))
        cols = int(self.table.get_property("n-columns"))
        self.table.resize(rows + 1, cols)
        self.table.attach(sev_frame, 0, 1, rows, rows + 1, xoptions=0, yoptions=0)
        self.table.attach(like_frame, 1, 2, rows, rows + 1, xoptions=0, yoptions=0)
        self.table.attach(if_frame, 2, 3, rows, rows + 1, yoptions=0)
        self.table.attach(then_frame, 3, 4, rows, rows + 1, yoptions=0)
        self.table.attach(do_frame, 4, 5, rows, rows + 1, yoptions=0)

        if plugin.fixable:
            print "Fixable"

        if plugin.report_bug:
            self.table.resize(rows + 1, cols + 1)
            report_button = gtk.Button()
            report_button.set_label(_("Report\nBug"))
            report_button.show()
            report_button.connect("clicked", self.report_bug, sig)
            self.table.attach(report_button, 5, 6, rows, rows + 1,xoptions=0, yoptions=0)
            print "Report_bug"

    def quit(self, widget):
        gtk.main_quit() 

    def report_bug(self, widget, sig):
        # If we don't have a bug_report_window yet, make a new one
        if self.bug_report_window is None:
            br = BugReport(self, sig)
            self.bug_report_window = br
        self.bug_report_window.main_window.show()

    def update_alerts(self, database, type, item):

        def new_siginfo_callback(sigs):
            for siginfo in sigs.signature_list:
                self.add_siginfo(siginfo)
                self.update_num_label()
                self.show_current_alert()
        if type == "add" or type == "modify": 
            async_rpc = self.database.query_alerts(item)
            async_rpc.add_callback(new_siginfo_callback)
   
    def update_num_label(self, empty=False):
        if empty is True:
            self.alert_count_label.set_text("")
            return
        self.alert_count_label.set_text(_("Alert %d of %d") % (self.current_alert+1, len(self.alert_list)))

    def get_siginfo_from_localid(self, local_id):
        for siginfo in self.alert_list:
            if siginfo.local_id == local_id:
                return siginfo
        return None

    def on_delete_check_toggled(self, widget):
        store, iter = self.treeview.get_selection().get_selected()
        if iter == None:
            return
        self.current_alert = store.get_value(iter, 0) - 1
        self.database.delete_signature(self.alert_list[self.current_alert].sig)
        self.delete_current_alert()
        self.show_all_button_clicked(widget)

    def on_delete_all_check_toggled(self, widget):
        for alert in self.alert_list:
            self.database.delete_signature(alert.sig)
        self.current_alert = 0
        self.alert_list = []
        self.empty_load()
        self.alert_list_window.hide()
        self.update_button_visibility()

    def on_delete_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list):
            self.database.delete_signature(self.alert_list[self.current_alert].sig)
            self.delete_current_alert()
            self.show_current_alert()
                        
    def delete_current_alert(self):
        key = self.alert_list[self.current_alert]
        del self.alert_list[key]
        if len(self.alert_list) == 0:
            self.empty_load()
        else:
            if self.current_alert > len(self.alert_list)-1:
                self.current_alert = len(self.alert_list)-1
                self.show_current_alert()
        
  
    def add_siginfo(self, new_sig):
        curr_siginfo = self.get_siginfo_from_localid(new_sig.local_id)
        if curr_siginfo is None:
            self.alert_list.append(new_sig)
        else:
            self.alert_list.remove(curr_siginfo)
            self.alert_list.append(new_sig)
            self.alert_list.sort(compare_alert)
               

    def grant_button_clicked(self, widget):
        # Grant access here
        # Stop showing the current alert that we've just granted access to
        try:
            dbus_proxy = DBusProxy()
            resp = dbus_proxy.run_fix(self.alert_list[self.current_alert].local_id)
            MessageDialog(resp)
        except dbus.DBusException, e:
            print e
            FailDialog(_("Unable to grant access."))

#        self.delete_current_alert()

    def delete_current_alert(self):
        del self.alert_list[self.current_alert]
        self.update_button_visibility()

        if len(self.alert_list) == 0:
            self.empty_load()
        else:
            if self.current_alert > len(self.alert_list)-1:
                self.current_alert = len(self.alert_list)-1
        self.show_current_alert()

    def show_current_alert(self):
        self.clear_rows()
        size = len(self.alert_list)
        self.update_button_visibility()
        
        if size  == 0:
            return

        size = size - 1
        if size < self.current_alert:
            self.current_alert = size
        sig = self.alert_list[self.current_alert]
        self.source_label.set_label(sig.spath)
        self.target_label.set_label(sig.tpath)
        if sig.tclass == "dir":
            tclass = "directory"
        else:
            tclass = sig.tclass
        self.class_label.set_label(_("On the %s:") % tclass)
        if len(sig.sig.access) == 1:
            self.access_title_label.set_label(_("Attempted this access:"))
        else:
            self.access_title_label.set_label(_("Attempted these accesses:"))
            
        self.access_label.set_label(",".join(sig.sig.access))

        total_priority, plugins = sig.get_plugins()

        sig.update_derived_template_substitutions()

        for p, args in plugins:
            self.add_row(p, sig, args, ((float(p.priority) / float(total_priority)) * 100))
        self.show_date(sig)

        self.alert_count_label.set_label(_("Alert %d of %d" % (self.current_alert + 1, len(self.alert_list))))
        
    def on_close_button_clicked(self, widget):
        gtk.main_quit()

    def close_alert_window(self, widget, event=None):
        self.alert_list_window.hide()
        return True

    def on_about_activate(self, widget):
        self.about_dialog.show()

    def on_previous_button_clicked(self, widget):
        if self.current_alert > 0:             
            self.current_alert -= 1
            self.show_current_alert()

    def on_next_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list)-1:
            self.current_alert += 1
            self.show_current_alert()
                
    def on_list_all_button_clicked(self, widget):
        date_format = "%e-%b-%y %R" 
        self.liststore.clear()
        ctr = 1
        for alert in self.alert_list:
            
            summary = "%s %s %s %s", alert.spath, alert.tclass, alert.tpath, ",".join(alert.sig.access)
	    self.liststore.append([ctr, os.path.basename(alert.spath), alert.tpath, alert.tclass, ",".join(alert.sig.access), alert.last_seen_date.format(date_format)])
            ctr = ctr + 1
       
        self.alert_list_window.show_all()
        
    def update_button_visibility(self):
        size = len(self.alert_list)
#        self.grant_button.hide()

        if size < 2:
            self.next_button.hide()
            self.previous_button.hide()

        if size == 0:
            self.delete_button.hide()
            self.ignore_button.hide()
            self.report_button.hide()
            self.list_all_button.hide()
            self.first_label.hide()
            self.latest_label.hide()
            self.occurance_label.hide()
            self.alert_count_label.hide()
            return

        self.delete_button.show()
        self.ignore_button.show()
        self.report_button.show()
        self.list_all_button.show()
        self.first_label.show()
        self.latest_label.show()
        self.occurance_label.show()
        self.alert_count_label.show()
        if size > 1:
            self.next_button.show()
            self.previous_button.show()
        
        self.next_button.set_sensitive(self.current_alert < (size - 1))
        self.previous_button.set_sensitive(self.current_alert != 0)

    def show(self):
        self.window.show()

    def hide(self):
        self.main_window.hide()
# BugReport is the window that pops up when you press the Report Bug button
class BugReport:
    def __init__(self, parent, siginfo):
        
        self.parent = parent
        self.gladefile = GLADE_DIRECTORY + "bug_report.glade"
        self.widget_tree = gtk.glade.XML(self.gladefile, domain=parent.domain)
        self.siginfo = siginfo
        self.hostname = self.siginfo.sig.host
        self.siginfo.host = _("(removed)")
        self.siginfo.environment.hostname = _("(removed)")
        self.siginfo.sig.host = _("(removed)")
        
        hash = self.siginfo.get_hash()
        self.summary = self.siginfo.summary()
        # Get the widgets we need
        self.main_window = self.widget("bug_report_window")
        self.error_submit_text = self.widget("error_submit_text")
        self.submit_button = self.widget("submit_button")
        self.cancel_button = self.widget("cancel_button")
        self.error_submit_text = self.widget("error_submit_text")

        # Construct and connect the dictionary
        dic = { "on_cancel_button_clicked" : self.cancel_button_clicked,
                "on_submit_button_clicked" : self.submit_button_clicked}
                
        self.main_window.connect("destroy", self.destroy)
        self.widget_tree.signal_autoconnect(dic)
        
        text_buf = gtk.TextBuffer()
        text_buf.set_text(self.siginfo.format_text().replace(self.hostname, _("(removed)")))
        self.error_submit_text.set_buffer(text_buf)

    def destroy(self, widget):
        # When we close the window let the parent know that it no longer exists
        self.parent.bug_report_window = None
        self.main_window.destroy()

    def cancel_button_clicked(self, widget):
        self.destroy(self.main_window)
    
    def idle_func(self):
        while gtk.events_pending():
            gtk.main_iteration()
    
    def submit_button_clicked(self, widget):
        main_window = self.main_window.get_root_window() 
        busy_cursor = gtk.gdk.Cursor(gtk.gdk.WATCH)
        ready_cursor = gtk.gdk.Cursor(gtk.gdk.LEFT_PTR)
        main_window.set_cursor(busy_cursor)
        self.idle_func()

        self.submit()

        main_window.set_cursor(ready_cursor)
        self.idle_func()

    def submit(self):
        text_buf = self.error_submit_text.get_buffer()
        content = text_buf.get_text(text_buf.get_start_iter(), text_buf.get_end_iter())
        signature = report.createAlertSignature("selinux-policy", 
                                                "setroubleshoot", 
                                                self.siginfo.get_hash(), 
                                                self.summary, 
                                                content)
 
        rc = report.report(signature, report.io.GTKIO.GTKIO(self.parent.accounts))
        self.destroy(self.main_window)

    def widget(self, name):
        return self.widget_tree.get_widget(name)

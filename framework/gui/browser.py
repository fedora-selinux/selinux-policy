#!/usr/bin/env python

# Author: Thomas Liu <tliu@redhat.com>
# Author: Dan Walsh <dwalsh@redhat.com>

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

package_list = set()
# The main security alert window
class BrowserApplet:
    """Security Alert Browser"""

    def on_show_me_clicked(self, widget):
        pass

    def empty_load(self):
        self.short_desc_label.set_text("No alerts to view.")
        self.clear_rows()
        self.alert_count_label.set_markup("<b>No alerts.</b>")
        self.date_label.set_markup("")

    def __init__(self, username=None, server=None, list=False, domain=None):
        self.RECT_SIZE = 30
        builder = gtk.Builder()
        builder.add_from_file("/usr/share/setroubleshoot/gui/browser.glade") 
        

        self.alert_list = {}
        server.connect('signatures_updated', self.update_alerts)
        self.pane = builder.get_object("solutions_pane")
        self.table = builder.get_object("solutions_table")
        self.window = builder.get_object("window1")
       
        self.severity_label = builder.get_object("severity_label")
        self.likelihood_label = builder.get_object("likelihood_label")
        self.if_label = builder.get_object("if_label")
        print self.if_label
        self.then_label = builder.get_object("then_label")
        self.do_label = builder.get_object("do_label")
        self.alert_count_label = builder.get_object("alert_count_label")
        self.short_desc_label = builder.get_object("short_des")
        self.date_label = builder.get_object("date_label")
        self.start_label = builder.get_object("start_label")
        self.occurance_label = builder.get_object("occurance_label")

        self.solutions_pane = builder.get_object("solutions_pane")
        self.solutions_pane.hide()

        self.solutions_vbox = builder.get_object("solutions_vbox")

        builder.connect_signals(self)       
        self.current_alert = 0
        self.username = username
        self.database = server
        self.server = server
        self.domain = domain
        self.window.show()
        self.empty_load()
        self.load_data()
        self.on_show_me_clicked(None)

    def update_alerts(self, database, type, item):
        def new_siginfo_callback(sigs):
            for siginfo in sigs.signature_list:
                if sig.local_id not in self.alert_list.keys():
                    self.alert_list[sig.local_id] = []
                self.alert_list[sig.local_id].append(sig)
            self.show_current_alert()

        if type == "add" or type == "modify": 
            async_rpc = self.database.query_alerts(item)
            async_rpc.add_callback(new_siginfo_callback)
   

    def time_since_days(self, before, after):

        time = after - before
        days = abs(time.days)
        if time.seconds > after.now().hour * 60 * 60 + after.now().minute * 60 + after.now().second:
            days += 1
        if days == 0:
            return _("Today")
        if days == 1:
            return _("Yesterday")
        # Internationilization wants this form.
        return P_("%d day ago", "%d days ago", days) % days
     
    def show_date(self, alert):
        from setroubleshoot.util import TimeStamp
        # Format the data that we get and display it in the appropriate places
        date_format = "%a %b %e, %Y %r %Z"
        alert_date = alert.last_seen_date
        start_date = alert.first_seen_date
        date_text = _("%s on %s") % (self.time_since_days(alert_date, TimeStamp()), alert_date.format(date_format))
        self.date_label.set_markup(date_text)
        start_label_text = _("%s" % start_date.format(date_format))
        self.start_label.set_markup(start_label_text)
        start_label_text = P_("%d time", "<b>%d times</b>", alert.report_count) % (alert.report_count)
        self.occurance_label.set_markup(start_label_text)

    def on_show_me_clicked(self, widget):
        self.solutions_pane.show()
        self.window.set_size_request(900, 630)

    def load_data(self):
        if self.database is not None:
            criteria = "*"
            async_rpc = self.database.query_alerts(criteria)
            async_rpc.add_callback(self.first_load)
            async_rpc.add_errback(self.database_error)

    def first_load(self, sigs):
        for sig in sigs.siginfos():
            if sig.local_id not in self.alert_list.keys():
                self.alert_list[sig.local_id] = []

            self.alert_list[sig.local_id].append(sig)
        self.show_current_alert()

    
    # TODO        
    def database_error(self, method, errno, strerror):
        pass



    def clear_rows(self):
        for child in self.table.get_children():
            self.table.remove(child)
        cols = int(self.table.get_property("n-columns"))
        self.table.resize(1, cols)

    def add_row(self, severity, likelihood, iff, then, do):

        sev_label = gtk.Image()
        pixmap = gtk.gdk.Pixmap(None, self.RECT_SIZE, self.RECT_SIZE, 24)
        cr = pixmap.cairo_create()
        bg_color = sev_label.get_style().bg[0]
        cr.set_source_color(bg_color)
        cr.paint()
        cr.set_source_rgb(0, 0, 0)
        cr.rectangle(0, 0, self.RECT_SIZE, self.RECT_SIZE)
        cr.fill()
        if severity == "red":
            cr.set_source_rgb(1, 0 ,0)
        elif severity == "yellow":
            cr.set_source_rgb(1, 1 ,0)
        elif severity == "green":
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


        if_label = gtk.Label()
        if_label.set_markup(iff)
        then_label = gtk.Label()
        then_label.set_markup(then)
        do_label = gtk.Label()
        do_label.set_markup(do)
        if_label.set_line_wrap(True)
        then_label.set_line_wrap(True)
        if_label.wrap_mode = gtk.WRAP_WORD
        then_label.wrap_mode = gtk.WRAP_WORD
        do_label.wrap_mode = gtk.WRAP_WORD
        then_label.set_alignment(0.0, 0.0)
        if_label.set_alignment(0.0, 0.0)
        do_label.set_alignment(0.0, 0.0)
        do_label.set_line_wrap(True)
        if_label.set_width_chars(25)
        if_label.set_justify(gtk.JUSTIFY_LEFT)
        then_label.set_width_chars(25)
        then_label.set_justify(gtk.JUSTIFY_LEFT)
        do_label.set_width_chars(25)
        do_label.set_justify(gtk.JUSTIFY_LEFT)
        then_label.set_padding(10, 10)
        if_label.set_padding(10, 10)
        do_label.set_padding(10, 10)
        sev_label.show()
        like_label.show()
        if_label.show()
        then_label.show()
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
        if_frame.add(if_label)
        if_frame.set_size_request(220, 90)

        then_frame = gtk.Frame()
        then_frame.set_shadow_type(gtk.SHADOW_OUT)
        then_frame.show()
        then_frame.add(then_label)
        then_frame.set_size_request(220, 90)

        do_frame = gtk.Frame()
        do_frame.set_shadow_type(gtk.SHADOW_OUT)
        do_frame.show()
        box = gtk.HBox()
        do_frame.add(box)
        do_frame.set_size_request(220, 90)

        box.pack_start(do_label)
        #do_button = gtk.Button(label = "Show\nme how")
        #box.pack_end(do_button)

        box.show()
        #do_button.show()


        rows = int(self.table.get_property("n-rows"))
        cols = int(self.table.get_property("n-columns"))
        self.table.resize(rows + 1, cols)
        self.table.attach(sev_frame, 0, 1, rows, rows + 1, yoptions=0)
        self.table.attach(like_frame, 1, 2, rows, rows + 1, yoptions=0)
        self.table.attach(if_frame, 2, 3, rows, rows + 1, yoptions=0)
        self.table.attach(then_frame, 3, 4, rows, rows + 1, yoptions=0)
        self.table.attach(do_frame, 4, 5, rows, rows + 1, yoptions=0)


    def quit(self, widget):
        gtk.main_quit() 

    def update_alerts(self, database, type, item):

        def new_siginfo_callback(sigs):
            for siginfo in sigs.signature_list:
                if siginfo.local_id not in self.do_not_notify_list:
                    self.add_siginfo(siginfo)
                    self.update_num_label()
                    self.prune_alert_list()
                    self.show_current_alert()
        if type == "add" or type == "modify": 
            async_rpc = self.database.query_alerts(item)
            async_rpc.add_callback(new_siginfo_callback)
   
    def check_do_not_notify(self, siginfo):
        for id in self.do_not_notify_list:
            if id == siginfo.local_id:
                return False
        return True

    def prune_alert_list(self):
        self.alert_list = filter(self.check_do_not_notify, self.alert_list)

    def get_siginfo_from_localid(self, local_id):
        for siginfo in self.alert_list:
            if siginfo.local_id == local_id:
                return siginfo
        return None

    def on_delete_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list):
            key = self.alert_list.keys()[self.current_alert]
            alerts = self.alert_list[key]
            for a in alerts:
                self.database.delete_signature(a.sig)
            self.delete_current_alert()
                        
    def delete_current_alert(self):
        key = self.alert_list.keys()[self.current_alert]
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
               

    def report_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list):
            if widget.get_label() == _("Update Policy"):
                self.install_button_clicked(widget)
                widget.set_label(_("Report Bug..."))
                return
            # If we don't have a bug_report_window yet, make a new one
            if self.bug_report_window is None:
                br = BugReport(self, self.alert_list[self.current_alert])
                self.bug_report_window = br
            self.bug_report_window.main_window.show()

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
        
        if size  == 0:
            return

        size = size - 1
        if size < self.current_alert:
            self.current_alert = size
        key = self.alert_list.keys()[self.current_alert]
        alerts = self.alert_list[key]
        for alert in alerts:
            self.add_row(alert.level, alert.probability, alert.if_text, alert.then_text, alert.do_this)
            self.short_desc_label.set_markup(alert.solution.summary)
        
        self.show_date(alerts[0])

        self.alert_count_label.set_markup(_("<b>Alert %d of %d</b>" % (self.current_alert + 1, len(self.alert_list))))
        

    def on_close_button_clicked(self, widget):
        gtk.main_quit()

    def on_previous_button_clicked(self, widget):
        if self.current_alert > 0:             
            self.current_alert -= 1
            self.show_current_alert()

    def on_next_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list)-1:
            self.current_alert += 1
            self.show_current_alert()

                
    def show(self):
        self.window.show()

    def hide(self):
        self.main_window.hide()



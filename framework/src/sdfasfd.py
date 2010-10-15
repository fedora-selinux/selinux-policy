#!/usr/bin/env python

# Author: Thomas Liu <tliu@redhat.com>

import gettext
from subprocess import *
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

    def __init__(self, username=None, server=None, list=False, domain=None):
        self.RECT_SIZE = 30
        builder = gtk.Builder()
        builder.add_from_file("/usr/share/setroubleshoot/gui/browser.glade") 
        

        self.alert_list = {}
        server.connect('signatures_updated', self.update_alerts)
        self.pane = builder.get_object("solutions_pane")
        self.table = builder.get_object("solutions_table")
        self.window = builder.get_object("window1")
        self.window.set_size_request(1000, 630)
       
        self.severity_label = builder.get_object("severity_label")
        self.likelihood_label = builder.get_object("likelihood_label")
        self.if_label = builder.get_object("if_label")
        self.then_label = builder.get_object("then_label")
        self.do_label = builder.get_object("do_label")

        self.severity_label.set_size_request(50, 20)
        self.likelihood_label.set_size_request(50, 20)
        self.if_label.set_size_request(200, 20)
        self.then_label.set_size_request(200, 20)
        self.do_label.set_size_request(200, 20)

        self.solutions_vbox = builder.get_object("solutions_vbox")

        builder.connect_signals(self)       
        self.current_alert = 0
        self.username = username
        self.database = server
        self.server = server
        self.domain = domain
        self.window.show()


    def update_alerts(self, database, type, item):
        def new_siginfo_callback(sigs):
            for siginfo in sigs.signature_list:
                print "SIG"
        if type == "add" or type == "modify": 
            async_rpc = self.database.query_alerts(item)
            async_rpc.add_callback(new_siginfo_callback)
   



    def load_data(self):
        if self.database is not None:
            criteria = "*"
            async_rpc = self.database.query_alerts(criteria)
            async_rpc.add_callback(self.first_load)
            async_rpc.add_errback(self.database_error)

    def first_load(self, sigs):
        for sig in sigs.siginfos():
            print sig.local_id

    
    # TODO        
    def database_error(self, method, errno, strerror):
        pass




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


        if_label = gtk.Label(iff)
        then_label = gtk.Label(then)
        do_label = gtk.Label(do)
        if_label.set_line_wrap(True)
        then_label.set_line_wrap(True)
        do_label.set_line_wrap(True)
        if_label.set_width_chars(25)
        if_label.set_justify(gtk.JUSTIFY_LEFT)
        then_label.set_width_chars(25)
        then_label.set_justify(gtk.JUSTIFY_LEFT)
        do_label.set_width_chars(25)
        do_label.set_justify(gtk.JUSTIFY_LEFT)
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
        if_frame.set_size_request(200, 60)

        then_frame = gtk.Frame()
        then_frame.set_shadow_type(gtk.SHADOW_OUT)
        then_frame.show()
        then_frame.add(then_label)
        then_frame.set_size_request(200, 60)

        do_frame = gtk.Frame()
        do_frame.set_shadow_type(gtk.SHADOW_OUT)
        do_frame.show()
        box = gtk.HBox()
        do_frame.add(box)
        do_frame.set_size_request(300, 60)

        box.pack_start(do_label)
        do_button = gtk.Button(label = "Show\nme how")
        box.pack_end(do_button)

        box.show()
        do_button.show()


        rows = int(self.table.get_property("n-rows"))
        cols = int(self.table.get_property("n-columns"))
        self.table.resize(rows + 1, cols)
        self.table.attach(sev_frame, 0, 1, rows, rows + 1, yoptions=0)
        self.table.attach(like_frame, 1, 2, rows, rows + 1, yoptions=0)
        self.table.attach(if_frame, 2, 3, rows, rows + 1, yoptions=0)
        self.table.attach(then_frame, 3, 4, rows, rows + 1, yoptions=0)
        self.table.attach(do_frame, 4, 5, rows, rows + 1, yoptions=0)




    def install_button_clicked(self, widget):
        if not os.access(UPDATE_PROGRAM, os.X_OK):
            return

        if os.fork() == 0:
            os.execv(UPDATE_PROGRAM, [])

    def install_cancel_button_clicked(self, widget):
        self.install_window.hide()

    def done_button_clicked(self, widget):
        self.install_window.hide()
   
    def read_pipe(self):
        while 1:
            self.updaterpipe.poll()
            if self.updaterpipe.returncode != 0:
                self.current_policy_label.set_markup("<small><b>%s</b></small>" % _("Error while checking policy version."))
                yield False
            line = self.updaterpipe.stdout.readline()            
            if line.find(_("newer")) != -1:
                self.report_button.set_tooltip_text(_("There is a newer version of policy available.  Updating your policy may fix the denial that you having problems with."))
                self.current_policy_label.set_markup(self.current_policy_label.get_label() + "<small><b>%s: %s</b></small>" % (_("Newest Version"), line.split(" ")[1])) 
                if os.access(UPDATE_PROGRAM, os.X_OK):
                    self.report_button.set_label(_("Update Policy"))
                yield True
            if line.find(_("current")) != -1:
                self.current_policy_label.set_markup("<small><b>%s: %s</b></small>\n" % (_("Policy Version"), line.split(" ")[1]))
                yield True
            if line.find("error") != -1:
                yield False
            if line.find("done") != -1:
                yield False

    def empty_load(self):
        self.date_label.set_markup("")
        self.start_label.set_markup("")
        self.access_label.set_markup("<span size='large' weight='bold' face='verdana'>%s</span>" % _("No alerts to view."))
        self.summary_doc.clear()
        self.summary_doc.open_stream("text/html")
        self.detail_doc.clear()
        self.detail_doc.open_stream("text/html")
        html_body = "<html><head><style type=\"text/css\">body{top:0;left:0;margin:0;padding:15;color:#000;background:#ede9e3;}</style> </head><body></body></html>"
        html_doc = html_document(html_body)
        html_body_white = "<html><head><style type=\"text/css\">body{top:0;left:0;margin:0;padding:15;color:#000;background:#ffffff;}</style> </head><body></body></html>"
        html_doc_white = html_document(html_body_white)
        self.summary_doc.write_stream(html_doc)
        self.detail_doc.write_stream(html_doc_white)
        self.summary_doc.close_stream()
        self.grant_button.hide()
        self.report_button.hide()
        self.copy_button.show()
        self.delete_button.show()
        self.notify_check.hide()
        self.update_num_label(empty=True)
        self.warning_label.set_markup(_("<span face=\"Helvetica\" size='large' weight='bold'>SELinux Troubleshoot Browser</span>"))
    def on_copy_button_clicked(self, widget):
        self.clipboard.set_text(self.alert_list[self.current_alert].format_text())

    def on_delete_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list):
            self.database.delete_signature(self.alert_list[self.current_alert].sig)
            self.delete_current_alert()

    def close_window(self, widget, event):
        widget.hide()
        return True
    def close_alert_window(self, widget, event):
        widget.hide()
        return True

    def delete_check_toggled(self, widget):
        store, iter = self.treeview.get_selection().get_selected()
        if iter == None:
            return
        self.current_alert = store.get_value(iter, 0) - 1
        self.database.delete_signature(self.alert_list[self.current_alert].sig)
        self.delete_current_alert()
        self.show_all_button_clicked(widget)

    def view_all_check_toggled(self, widget):
        pass

    def delete_all_check_toggled(self, widget):
        for alert in self.alert_list:
            self.database.delete_signature(alert.sig)
        self.current_alert = 0
        self.alert_list = []
        self.empty_load()
        self.alert_list_window.hide()
        self.update_button_visibility()

    def show_about(self, widget):
        self.about_dialog.show()
    def hide_about(self, widget):
        self.about_dialog.hide()
    def link_clicked(self, doc, link):
        launch_web_browser_on_url(link) 
    def make_treeview(self):
        tmsort = gtk.TreeModelSort(self.liststore)
       
        cols = [_("#"), _("Summary"), _("Count"), _("Command"), _("Date")]
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
            #if c=="Count":
               # col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
               # col.set_fixed_width(30)
            if x==1:
                col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
                col.set_fixed_width(400)
            x +=1 
        self.treeview.set_headers_clickable(True)
        self.treeview_window.add(self.treeview)
        self.treeview.connect("row-activated", self.row_activated)
    
    def show_all_button_clicked(self, widget):
        date_format = "%e-%b-%y %R" 
        self.liststore.clear()
        for alert in self.alert_list:
	    self.liststore.append([self.alert_list.index(alert)+1, alert.solution.summary.strip(),alert.report_count, alert.spath, alert.last_seen_date.format(date_format)])
       
        self.alert_list_window.show_all()
        
    def row_activated(self, x, y, z):
        store, iter = x.get_selection().get_selected()
        if iter == None:
            return
        self.current_alert = store.get_value(iter, 0) - 1
        self.alert_list_window.hide()
        self.show_current_alert()

    def create_htmlview(self, container):
       view = gtkhtml2.View()
       doc = gtkhtml2.Document()
       view.set_document(doc)
       container.add(view)
       return (view, doc)

    def set_prefs(self):
        self.do_not_notify_list = []
        self.current_alert = 0
        filename = PREF_PATH
        if os.path.exists(filename):
            id = None
            f = open(filename, "r")
            pairs = f.readlines()
            for rec in pairs:
                pair = rec[:-1]
                if pair.find("pos") >= 0:
                    id = pair.split("=")[1]
                if pair.find("dontnotify") >= 0:
                    name, val = pair.split("=")
                    for id in val.split(","):
                        if len(id):
                            self.do_not_notify_list.append(id)
                if pair.find("bugzilla_user") >= 0:
                    if len(pair.split("=")) == 2:
                        self.accounts.addAccount("bugzilla.redhat.com",pair.split("=")[1])
                        self.remember_me = True

            f.close()
            for sig in self.alert_list:
                if sig.local_id == id:
                    self.current_alert = self.alert_list.index(sig)

    def quit(self, widget):
        filename = PREF_PATH 
        try:
            file = open(filename, "w")
        except IOError:
            gtk.main_quit()
            return
        first = True
        file.write("dontnotify=")
        for id in self.do_not_notify_list:
            for alert in self.alert_list:
                if alert.local_id == id:
                    self.server.set_filter(alert.sig, self.username, FILTER_ALWAYS, '')
            if first:
                first = False
            else:
                file.write(",")
            file.write(id)

        saved_id = ""

        if len(self.alert_list) > 0:
            file.write("\nlast=" + self.alert_list[-1].local_id)    
            try:
                while self.alert_list[self.current_alert].local_id in self.do_not_notify_list:
                    self.current_alert = self.current_alert + 1
            except IndexError:
                self.current_alert = self.current_alert - 1

            while self.current_alert > 0 and self.alert_list[self.current_alert].local_id in self.do_not_notify_list:
                self.current_alert = self.current_alert - 1
            saved_id = str(self.alert_list[self.current_alert].local_id)
        file.write("\npos=" + saved_id)
        accountName = "bugzilla.redhat.com"
        if self.accounts.hasAccount(accountName):
            accountInfo = self.accounts.lookupAccount(accountName)
            if accountInfo.remember_me:
                file.write("\nbugzilla_user=" + accountInfo.username)
        
        file.write("\n");
        file.close()
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
        self.main_window.show()
        self.update_button_visibility()
        size = len(self.alert_list)
        
        if size  == 0:
            return

        size = size - 1
        if size < self.current_alert:
            self.current_alert = size
        
        self.notify_check.show()
        self.report_button.show()
        alert = self.alert_list[self.current_alert]
        self.show_alert(alert)
        if alert.fixable == "True":
            self.grant_button.show()
            self.report_button.hide()
        if alert.level == "red":
            self.warning_label.set_markup(_("<span face=\"Helvetica\" size='large' weight='bold'>Your system could be seriously compromised!</span>"))
            self.image.set_from_stock(gtk.STOCK_STOP, gtk.ICON_SIZE_DIALOG)
            # I don't know why we did this...
            #self.report_button.hide()
        elif alert.level == "green":
            self.report_button.hide()
        else:
            self.warning_label.set_markup(_("<span face=\"Helvetica\" size='large' weight='bold'>SELinux has detected suspicious behavior on your system</span>"))
            self.image.set_from_stock(gtk.STOCK_DIALOG_WARNING, gtk.ICON_SIZE_DIALOG)


    def notify_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list):
            curr_id = self.alert_list[self.current_alert].local_id

            if widget.get_active() == True and self.do_not_notify_list.count(curr_id) == 0:
                self.do_not_notify_list.append(curr_id)
            elif self.notify_check.get_active() == False:
                if self.do_not_notify_list.count(curr_id) > 0:
                    self.do_not_notify_list.remove(curr_id)

        #self.vpane.set_position(-140)
    def previous_button_clicked(self, widget):
        if self.current_alert > 0:             
            self.current_alert -= 1
            self.show_current_alert()
            self.update_dnn_checkbox()   

    def update_dnn_checkbox(self):
        self.notify_check.set_active(False)
        curr_id = self.alert_list[self.current_alert].local_id
        if self.do_not_notify_list.count(curr_id) > 0:
            self.notify_check.set_active(True)

    def next_button_clicked(self, widget):
        if self.current_alert < len(self.alert_list)-1:
            self.current_alert += 1
            self.show_current_alert()
            self.update_dnn_checkbox()
                
    # Check and update the visibility of the next and previous buttons
    # They should be hidden if there is only a single alert
    def update_button_visibility(self):
        size = len(self.alert_list)
        self.grant_button.hide()
        self.report_button.hide()

        if size < 2:
            self.next_button.hide()
            self.previous_button.hide()

        if size == 0:
            self.notify_check.hide()
            self.copy_button.hide()
            self.delete_button.hide()
            self.show_all_button.hide()
            return

        self.show_all_button.show()
        self.notify_check.show()
        self.copy_button.show()
        self.delete_button.show()
        if size > 1:
            self.next_button.show()
            self.previous_button.show()
        
        self.next_button.set_sensitive(self.current_alert < (size - 1))
        self.previous_button.set_sensitive(self.current_alert != 0)
            
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
     
    def show(self):
        self.window.show()

    def hide(self):
        self.main_window.hide()

    # pass this a siginfo. 
    def show_alert(self, alert):
        from setroubleshoot.util import TimeStamp
        # Format the data that we get and display it in the appropriate places
        date_format = "%a %b %e, %Y at %r %Z"
        alert_date = alert.last_seen_date
        start_date = alert.first_seen_date
        date_text = _("<span foreground='#555555'>%s on %s</span>") % (self.time_since_days(alert_date, TimeStamp()), alert_date.format(date_format))
        self.date_label.set_markup(date_text)
        start_label_text = P_("This alert has occurred <b>%d time</b> since %s", "This alert has occurred <b>%d times</b> since %s", alert.report_count) % (alert.report_count, start_date.format(date_format))

        self.start_label.set_markup(start_label_text)
        parts = alert.description_adjusted_for_permissive().split("\n")
        parts = filter(lambda x:x!="", parts)
        parts = map(lambda x: x.strip(), parts)
        desc = ""
        for x in parts:
            desc += x
            desc += " "
        parts = alert.solution.summary.split("\n")
        parts = filter(lambda x:x!="", parts)
        parts = map(lambda x: x.strip(), parts)
        desc = ""
        for x in parts:
            desc += x
            desc += " "
        self.access_label.set_markup("<span size='medium' weight='bold' face='verdana'>%s</span>" % desc)
        self.detail_doc.clear()
        self.detail_doc.open_stream("text/html")
        html_body = alert.format_html()
        html_doc = html_document(html_body)
        self.detail_doc.write_stream(html_doc)
        self.detail_doc.close_stream()
        
        self.summary_doc.clear()
        self.summary_doc.open_stream("text/html")
       
        if alert.button_text is not None:
            for obj in self.grant_button.child.child.get_children():
                if isinstance(obj, gtk.Label):
                    obj.set_text(alert.button_text)
        parts = alert.description_adjusted_for_permissive().split("\n")
        parts = filter(lambda x:x!="", parts)
        parts = map(lambda x: x.strip(), parts)
        desc = ""
        for x in parts:
            desc+=x
            desc+= " "


        html_body = "<html><head><style type=\"text/css\">body{top:0;left:0;margin:0;padding:15;color:#000;background:#ede9e3;}</style> </head><body>%s</body></html>" % desc
        
        html_doc = html_document(html_body)
        self.summary_doc.write_stream(html_doc)
        self.summary_doc.close_stream() 

        self.update_num_label() 
    
    def update_num_label(self, empty=False):
        if empty is True:
            self.alert_num_label.set_markup("")
            return
        self.alert_num_label.set_markup(_("Alert<span weight='bold' size='large' face='verdana'> %d</span> of <span weight='bold' size='large' face='verdana'>%d</span>") % (self.current_alert+1, len(self.alert_list)))
    # When you activate the expander, we need to resize the frame that displays data
    # and also the size of the window.  We also need to move some widgets.
    def expander_activate(self, widget):
        if self.expander.get_expanded() == True:
            if self.main_window.get_size()[1] > 460:
                self.main_window.resize(self.main_window.get_size()[0], 460)
            self.scrolledwindow1.hide()
        elif self.expander.get_expanded() == False:
            if self.main_window.get_size()[1] < 685:
                self.main_window.resize(self.main_window.get_size()[0], 685)
            self.scrolledwindow1.show()
        self.vpane.set_position(-140)

    def widget(self, name):
        return self.widget_tree.get_widget(name)
    
    def load_data(self):
        if self.database is not None:
            criteria = "*"
            async_rpc = self.database.query_alerts(criteria)
            async_rpc.add_callback(self.first_load)
            async_rpc.add_errback(self.database_error)

    def first_load(self, sigs):
        for sig in sigs.siginfos():
            self.alert_list.append(sig)
        self.set_prefs()
        self.prune_alert_list()
        self.show_current_alert()

    
    # TODO        
    def database_error(self, method, errno, strerror):
        pass

def compare_alert(a, b):
    return cmp(a.last_seen_date, b.last_seen_date)


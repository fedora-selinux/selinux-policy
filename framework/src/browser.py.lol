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
import bugzilla, xmlrpclib
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

class DBusProxy (object):
    def __init__ (self):
        self.bus = dbus.SystemBus ()
        self.dbus_object = self.bus.get_object ("org.fedoraproject.SetroubleshootFixit", "/org/fedoraproject/SetroubleshootFixit/object")

    @polkit.enable_proxy
    def run_fix (self, local_id):
        return self.dbus_object.run_fix (local_id, dbus_interface = "org.fedoraproject.SetroubleshootFixit")


# BugReport is the window that pops up when you press the Report Bug button
class BugReport:
    def __init__(self, parent, siginfo):
        
        self.parent = parent
        self.gladefile = GLADE_DIRECTORY + "bug_report.glade"
        self.widget_tree = gtk.glade.XML(self.gladefile, domain=parent.domain)
        self.siginfo = siginfo
        self.hostname = self.siginfo.host
        self.siginfo.host = _("(removed)")
        self.siginfo.environment.hostname = _("(removed)")
        self.siginfo.sig.host = _("(removed)")
        
        hash = self.siginfo.get_hash()
        self.summary = self.siginfo.solution.summary
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
        content += "\nHash String generated from  " + self.siginfo.get_hash_str()
        file = tempfile.NamedTemporaryFile(delete=False)
        file.write(content)
        file.close()
        content += "\naudit2allow suggests:" + run_audit2allow(file.name) 
        os.remove(file.name)

        signature = report.createAlertSignature("selinux-policy", 
                                                "setroubleshoot", 
                                                self.siginfo.get_hash(), 
                                                self.summary, 
                                                content)
 
        rc = report.report(signature, report.io.GTKIO.GTKIO(self.parent.accounts))
        self.destroy(self.main_window)

    def widget(self, name):
        return self.widget_tree.get_widget(name)

def timeout_callback(bar):
    bar.pulse()
    return True

class FailDialog():
    def __init__(self, message):
        dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_ERROR,
                                gtk.BUTTONS_OK,
                                message)
        dlg.set_title(_("Sealert Error"))
        dlg.set_position(gtk.WIN_POS_MOUSE)
        dlg.show_all()
        rc = dlg.run()
        dlg.destroy()

class MessageDialog():
    def __init__(self, message):
        dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_INFO,
                                gtk.BUTTONS_OK,
                                message)
        dlg.set_title(_("Sealert Message"))
        dlg.set_position(gtk.WIN_POS_MOUSE)
        dlg.show_all()
        rc = dlg.run()
        dlg.destroy()

def run_audit2allow(file):
    import commands
    command = "audit2allow -i " + file
    rc, output = commands.getstatusoutput(command)
    if rc==0:
        return output
    return "\naudit2allow is not installed."

package_list = set()
# The main security alert window
class BrowserApplet:
    """Security Alert Browser"""
    def __init__(self, username=None, server=None, list=False, domain=None):
        self.current_alert = 0
        self.username = username
        self.database = server
        self.server = server
        self.domain = domain
        server.connect('signatures_updated', self.update_alerts)
        # TODO Does this need anything?
        self.window_delete_hides = True
        # This is to be filled with siginfos.
        self.alert_list = []
        self.do_not_notify_list = []
        
        #set the glade filg
        self.gladefile = GLADE_DIRECTORY + "browser.glade"
        self.widget_tree = gtk.glade.XML(self.gladefile, domain=domain)

        # Get widgets so we can work with them
        self.install_window = self.widget("install_window")
        self.status_view = self.widget("status_view")
        self.install_label = self.widget("install_label")
        self.new_policy_box = self.widget("new_policy_box")
	self.new_policy_box.hide()
        self.current_policy_label = self.widget("current_policy_label")
        self.install_cancel_button = self.widget("install_cancel_button")
        self.install_button = self.widget("install_button")
        self.done_button = self.widget("done_button")
        self.main_window = self.widget("main_window")
        self.close_button = self.widget("close_button")
        self.next_button = self.widget("next_button")
        self.previous_button = self.widget("previous_button")
        self.alert_num_label = self.widget("alert_num_label")
        self.expander = self.widget("expander1")
        self.report_button = self.widget("report_button")
        self.access_label = self.widget("access_label")
        self.main_container = self.widget("main_container")
        self.notify_check = self.widget("notify_check")
        self.inner_frame = self.widget("inner_frame")
        self.text_label = self.widget("text_label")
        self.image = self.widget("image")
        self.copy_button = self.widget("copy_button")
        self.delete_button = self.widget("delete_button")
        self.warning_label = self.widget("warning_label")
        self.date_label = self.widget("date_label")
        self.error_text = self.widget("error_text")
        self.scrolledwindow1 = self.widget("scrolledwindow1")
        self.vpane = self.widget("vpaned1")
        self.scrolledwindow2 = self.widget("scrolledwindow2")
        self.main_window.connect("destroy", self.quit)
        self.grant_button = self.widget("grant_button")
        self.show_all_button = self.widget("show_all_button")
        self.alert_list_window = self.widget("alert_list_window") 
        self.start_label = self.widget("start_label")
        self.image.set_from_stock(gtk.STOCK_DIALOG_WARNING, gtk.ICON_SIZE_DIALOG)
        self.list_window_box = self.widget("vbox1")
        self.treeview_window = self.widget("treeview_window") 
        # Make a gtkhtml view and doc and stick it in the scrolled window
        self.detail_view, self.detail_doc = self.create_htmlview(self.scrolledwindow1)
        self.detail_doc.connect("link-clicked", self.link_clicked)
        self.scrolledwindow1.show_all()
        self.delete_all_check = self.widget("delete_all_check") 
        self.delete_check = self.widget("delete_check") 
        self.summary_view, self.summary_doc = self.create_htmlview(self.scrolledwindow2)
        self.summary_doc.connect("link-clicked", self.link_clicked)
        self.scrolledwindow2.show_all()
        self.alert_list_window.hide()
        self.clipboard = gtk.Clipboard() 
        self.about_dialog = self.widget("aboutdialog1")
        self.about_dialog.hide()
        self.about_dialog.connect("response", self.close_window)
        for obj in self.copy_button.child.child.get_children():
            if isinstance(obj, gtk.Label):
		        obj.set_text(_("Copy to Clipboard"))
        self.bug_report_window = None
        self.main_window.move(self.main_window.get_position()[0], 75)

        self.accounts = report.accountmanager.AccountManager()

        # construct and connect the dictionary
        dic = { "on_main_window_destroy" : self.quit,
                "on_expander1_activate" : self.expander_activate,
                "on_copy_button_clicked" : self.on_copy_button_clicked,
                "on_delete_button_clicked" : self.on_delete_button_clicked,
                "on_previous_button_clicked" : self.previous_button_clicked,
                "on_show_all_button_clicked" : self.show_all_button_clicked,
                "on_next_button_clicked" : self.next_button_clicked,
                "on_notify_button_clicked" : self.notify_button_clicked,
                "on_report_button_clicked" : self.report_button_clicked,
                "on_grant_button_clicked" : self.grant_button_clicked,
                "on_delete_check_toggled" : self.delete_check_toggled,
                "on_delete_all_check_toggled" : self.delete_all_check_toggled,
                "on_view_all_check_toggled" : self.view_all_check_toggled,
                "on_close_button_clicked" : self.quit,
                "on_install_button_clicked" : self.install_button_clicked,
                "on_install_cancel_button_clicked" : self.install_cancel_button_clicked,
                "on_done_button_clicked" : self.done_button_clicked,
                "on_imagemenuitem5_activate" : self.quit,
                "on_imagemenuitem10_activate" : self.show_about}
        self.alert_list_window.connect("delete-event", self.close_alert_window)
        self.about_dialog.connect("delete-event", self.close_window)
        self.widget_tree.signal_autoconnect(dic)
        self.update_button_visibility()
        self.load_data()
        self.liststore = gtk.ListStore(int, str, int, str, str) 
        self.make_treeview()

        self.updaterpipe = Popen(["/usr/bin/python", "/usr/share/setroubleshoot/updater.py"], stdout=PIPE)
        gobject.timeout_add(1000, self.read_pipe().next)
        if len(self.alert_list) == 0:
            self.empty_load()
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
            lines = self.updaterpipe.stdout.readlines()            
            for line in lines:
                if line.find(_("newer")) != -1:
                    self.report_button.set_tooltip_text(_("There is a newer version of policy available.  Updating your policy may fix the denial that you having problems with."))
                    self.current_policy_label.set_markup(self.current_policy_label.get_label() + "<small><b>%s: %s</b></small>" % (_("Newest Version"), line.split(" ")[1][:-1])) 
                    if os.access(UPDATE_PROGRAM, os.X_OK):
                        self.report_button.set_label(_("Update Policy"))
                    yield True
                if line.find(_("current")) != -1:
                    self.current_policy_label.set_markup("<small><b>%s: %s</b></small>" % (_("Polcy Version"), line.split(" ")[1]))
                    yield True
                if line.find("error") != -1:
                    self.current_policy_label.set_markup("") 
                    yield False
                if line.find("done") != -1:
                    yield False
            if self.updaterpipe.poll() != None:
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
        self.main_window.present()

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


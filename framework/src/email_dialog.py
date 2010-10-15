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

__all__ = ['EmailDialog']

# This import must come before importing gtk to silence warnings
from setroubleshoot.gui_utils import *

import pygtk
pygtk.require("2.0")
import gtk

import gobject 


from setroubleshoot.errcode import *
from setroubleshoot.gui_utils import *
from setroubleshoot.signature import *
from setroubleshoot.util import *
from setroubleshoot.log import *

#------------------------------------------------------------------------------

NUM_COLUMNS = 3
(PYOBJECT_COLUMN, FILTER_TYPE_COLUMN, ADDRESS_COLUMN) = range(NUM_COLUMNS)

#------------------------------------------------------------------------------

class EmailDialog(object):
    def __init__(self, recipient_set, parent=None):
        self.dlg = gtk.Dialog(_("Setroubleshoot Email Preferences"), parent, 0, None)

        self.dlg.set_default_size(300, 300)
        self.dlg.vbox.set_homogeneous(False)

        # Note: we add the OK and CANCEL buttons manually so that we can override their
        # automatic behavior of emitting a response signal and closing the dialog.
        # This allows us to validate before dismissing the dialog

        self.cancel_button = gtk.Button(stock=gtk.STOCK_CANCEL)
        self.cancel_button.connect('clicked', self.on_cancel_button_clicked)
        self.dlg.action_area.add(self.cancel_button)

        self.ok_button = gtk.Button(stock=gtk.STOCK_OK)
        self.ok_button.connect('clicked', self.on_ok_button_clicked)
        self.dlg.action_area.add(self.ok_button)

        self.dlg.set_default_response(gtk.RESPONSE_OK)

        self.help_email_button = gtk.Button(stock=gtk.STOCK_HELP)
        self.help_email_button.connect('clicked', self.on_help_email_button_clicked)
        self.help_email_button.set_sensitive(True)
    
        self.delete_email_button = gtk.Button(stock=gtk.STOCK_DELETE)
        self.delete_email_button.connect('clicked', self.on_delete_email_button_clicked)
        self.delete_email_button.set_sensitive(False)
    
        self.add_email_button = gtk.Button(_('Add'))
        self.add_email_button.connect('clicked', self.on_add_email_button_clicked)
        self.add_email_button.set_sensitive(False)

        self.add_email_entry = gtk.Entry()
        self.add_email_entry.connect('changed', self.on_add_email_entry_changed)
        self.add_email_entry.connect('activate', self.on_add_email_entry_activate)

        self.init_list_view(recipient_set)

        self.dlg.vbox.pack_start(self.email_list, True, True, 0)
        hbox = gtk.HBox(False)
        self.dlg.vbox.pack_start(hbox, False, True, 0)
        hbox.pack_start(self.help_email_button, True, True, 0)
        hbox.pack_start(self.delete_email_button, True, True, 0)
        hbox.pack_start(self.add_email_button, True, True, 0)
        hbox.pack_start(self.add_email_entry, True, True, 0)

    def run(self):

        self.dlg.show_all()
        self.response = self.dlg.run()
        self.dlg.destroy()
        if self.response == gtk.RESPONSE_OK:
            return self.get_recipient_set()
        else:
            return None

    def get_recipient_set(self):
        recipient_list = []
        model = self.email_list_model
        iter = model.get_iter_first()
        while iter:
            recipient = model.get_value(iter, PYOBJECT_COLUMN)
            recipient_list.append(recipient)
            iter = model.iter_next(iter)
        recipient_set = SEEmailRecipientSet(recipient_list)
        return recipient_set
        
    def on_help_email_button_clicked(self, button):
        help_text = _('''\
This is a list of email addresses to whom alerts will be
sent.

To add an email address type the address in the
input box and click the Add button. Duplicate addresses
are not permitted.

To delete one or more email addresses select the addresses
in the list and click the Delete button or use the Delete key.
Or you may edit the address and clear its value.

To edit an address click the address to begin editing.

To sort the list differently click on the column heading.

To change the filtering option click on the filter type and
pick from the list. The filter applies to all alerts for this
email address.

''')
        display_help(help_text, parent=self.dlg)

    def on_delete_email_button_clicked(self, button):
        self.delete_recipients(self.get_selected_recipients())

    def on_add_email_button_clicked(self, button):
        self.commit_email_entry()

    def on_add_email_entry_changed(self, entry):
        text = entry.get_text().strip()
        if text:
            self.add_email_button.set_sensitive(True)
        else:
            self.add_email_button.set_sensitive(False)

    def on_cancel_button_clicked(self, button):
        self.dlg.response(gtk.RESPONSE_CANCEL)
        return True

    def on_ok_button_clicked(self, button):
        # if there is pending data in the entry box that has not yet been
        # committed when OK is clicked, commit it now and only close the
        # dialog if successful.

        if self.commit_email_entry():
            self.dlg.response(gtk.RESPONSE_OK)
        return True

    def clear_email_entry(self):
        self.add_email_button.set_sensitive(False)
        self.add_email_entry.set_text('')

    def on_add_email_entry_activate(self, entry):
        self.commit_email_entry()

    def commit_email_entry(self):
        text = self.add_email_entry.get_text().strip()
        if not text:
            return True
        return self.add_email(text)

    def add_email(self, address):
        if debug:
            log_gui.debug("add_email: address='%s'", address)
        address = address.strip()
        if not address:
            return False

        if not valid_email_address(address):
            display_error("invalid email address = '%s'" % address)
            return False

        self.clear_email_entry()

        if self.find_recipient(address) is not None:
            if debug:
                log_gui.debug("add_email: address='%s' already in list", address)
            return False
        self.new_model_row(SEEmailRecipient(address))
        return True

    def init_list_view(self, recipient_set):
        self.email_list = gtk.TreeView()
        self.email_list.connect('key_press_event', self.on_key_press)
        
        # create the base model
        self.email_list_model = gtk.ListStore(gobject.TYPE_PYOBJECT,# recipient
                                              gobject.TYPE_BOOLEAN, # filter_type
                                              gobject.TYPE_STRING)  # address

        # create an intermediate model to sort the rows with
        self.email_list_model_sort = gtk.TreeModelSort(self.email_list_model)

        # set the TreeView's model to the sortable model,
        # which is backed by the filtered model, which is backed by the base list store model
        self.email_list.set_model(self.email_list_model_sort)

        # set the TreeView's model to the sort model,
        self.email_list.set_model(self.email_list_model_sort)

        #
        # Now create each column and intitialize it's cell renderers, etc.
        #

        # --- recipient ---
        tv_column = gtk.TreeViewColumn()
        tv_column.set_visible(False)
        self.email_list.append_column(tv_column)

        # --- filter ---
        filter_model = gtk.ListStore(gobject.TYPE_INT,     # filter value
                                     gobject.TYPE_STRING)  # filter name

        max_string_len = 0
        for filter_type in [FILTER_AFTER_FIRST, FILTER_NEVER, FILTER_ALWAYS]:
            filter_string = filter_text[filter_type]
            max_string_len = max(max_string_len, len(filter_string))
            filter_model.append((filter_type, filter_string))

        context = self.email_list.get_pango_context()
        metrics = context.get_metrics(context.get_font_description())
        max_string_len += 1             # add a little cushion

        import pango
        filter_column_width = pango.PIXELS(metrics.get_approximate_char_width() * max_string_len)

        cell = gtk.CellRendererCombo()
        cell.set_property('model', filter_model)
        cell.set_property('has-entry', False)
        cell.set_property('editable', True)
        cell.set_property('text-column', 1)
        cell.connect( 'edited', self.filter_type_edited, self.email_list_model_sort, filter_model)
        tv_column = gtk.TreeViewColumn(_('Filter Type'), cell)
        tv_column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        tv_column.set_fixed_width(filter_column_width)
        tv_column.set_cell_data_func(cell, self.filter_type_cell_data, FILTER_TYPE_COLUMN)
        tv_column.set_sort_column_id(FILTER_TYPE_COLUMN)
        self.email_list_model_sort.set_sort_func(FILTER_TYPE_COLUMN, self.model_sort_func, FILTER_TYPE_COLUMN)
        self.email_list.append_column(tv_column)

        # --- address ---
        cell = gtk.CellRendererText()
        cell.connect('edited', self.on_address_edited)
        cell.set_property('editable', True)
        tv_column = gtk.TreeViewColumn(_('Email Address'), cell, text=ADDRESS_COLUMN)
        tv_column.set_cell_data_func(cell, self.text_cell_data, ADDRESS_COLUMN)
        tv_column.set_sort_column_id(ADDRESS_COLUMN)
        self.email_list_model_sort.set_sort_func(ADDRESS_COLUMN, self.model_sort_func, ADDRESS_COLUMN)
        self.email_list.append_column(tv_column)

        #
        # Some final properties
        #

        # alternate row color for easy reading
        self.email_list.set_rules_hint(True)

        # Set up the selection objects
        self.email_list_selection = self.email_list.get_selection()
        self.email_list_selection.set_mode(gtk.SELECTION_MULTIPLE)
        self.email_list_selection.connect('changed', self.on_selection_changed)

        # initially select first row
        self.email_list_selection.select_path((0))
        model, row_paths = self.email_list_selection.get_selected_rows()

        # set initial sort order
        self.email_list_model_sort.set_sort_column_id(ADDRESS_COLUMN, gtk.SORT_ASCENDING)

        self.init_recipients(recipient_set)


    def get_selected_recipients(self):
        model, row_paths = self.email_list_selection.get_selected_rows()
        infos = []
        for path in row_paths:
            iter = model.get_iter(path)
            recipient = model.get_value(iter, PYOBJECT_COLUMN)
            infos.append(recipient)
        return infos

    def delete_recipients(self, recipients):
        if recipients is None:
            return
        for recipient in recipients:
            recipient, model, iter = self.find_recipient(recipient.address)
            model.remove(iter)

    def find_recipient(self, address, model=None):
        if model is None:
            model = self.email_list_model
            
        address = address.strip()
        iter = model.get_iter_first()
        while iter:
            recipient = model.get_value(iter, PYOBJECT_COLUMN)
            if recipient.address == address:
                return recipient, model, iter
            iter = model.iter_next(iter)
        return None

    def on_selection_changed(self, selection):
        if debug:
            log_gui.debug("on_selection_changed(): selection=%s", [x[0] for x in selection.get_selected_rows()[1]])

        if selection.count_selected_rows():
            self.delete_email_button.set_sensitive(True)
        else:
            self.delete_email_button.set_sensitive(False)
            

        return True     # return True ==> handled, False ==> propagate

    def filter_type_cell_data(self, column, cell, model, iter, column_index):
        recipient = model.get_value(iter, PYOBJECT_COLUMN)
        cell.set_property('text', filter_text[recipient.filter_type]) 
        return

    def filter_type_edited(self, cell, path, new_text, tv_model, combo_model):
        iter = tv_model.get_iter(path)
        recipient = tv_model.get_value(iter, PYOBJECT_COLUMN)

        # Find the string, map it back to its numeric value
        filter_type = None
        for row in combo_model:
            if new_text == row[1]:
                filter_type = row[0]
        recipient.filter_type = filter_type
        return

    def update_model_row(self, iter, recipient):
        self.email_list_model.set(iter, PYOBJECT_COLUMN, recipient)

    def new_model_row(self, recipient):
        iter = self.email_list_model.append()
        self.update_model_row(iter, recipient)
        return iter

    def init_recipients(self, recipient_set):
        for recipient in recipient_set.recipient_list:
            self.new_model_row(recipient)

    def get_cell_data(self, model, iter, column_index):
        data = None
        recipient = model.get_value(iter, PYOBJECT_COLUMN)
        if recipient is None:
            return None

        if column_index == ADDRESS_COLUMN:
            data = recipient.address
        elif column_index == FILTER_TYPE_COLUMN:
            data = recipient.filter_type

        return data

    def text_cell_data(self, column, cell, model, iter, column_index):
        text = self.get_cell_data(model, iter, column_index)
        cell.set_property('text', text) 
        return

    def model_sort_func(self, model, iter1, iter2, column_index):
        data1 = self.get_cell_data(model, iter1, column_index)
        data2 = self.get_cell_data(model, iter2, column_index)
        return cmp(data1, data2)

    def get_base_iter_from_view_path(self, view_path):
        base_path = self.email_list_model_sort.convert_path_to_child_path(view_path)
        iter = self.email_list_model.get_iter(base_path)
        return iter

    def get_base_iter_from_x_y(self, x, y):
        view_path = self.email_list_model_sort.get_path_at_pos(x, y)
        if view_path is None:
            return None
        base_path = self.email_list_model_sort.convert_path_to_child_path(view_path)
        iter = self.email_list_model.get_iter(base_path)
        return iter

    def on_address_edited(self, cell_renderer, path, text):
        new_address = text.strip()
        if debug:
            log_gui.debug("on_address_edited: path=%s text='%s'", path, text)

        if new_address:
            if not valid_email_address(new_address):
                display_error("invalid email address = '%s'" % new_address)
                return

        iter = self.get_base_iter_from_view_path(path)
        recipient = self.email_list_model.get_value(iter, PYOBJECT_COLUMN)

        if not new_address:
            self.email_list_model.remove(iter)
            return
        recipient.address = new_address
        
    def on_key_press(self, widget, event):
        keyname = gtk.gdk.keyval_name(event.keyval)
        if keyname == 'Delete':
            self.delete_recipients(self.get_selected_recipients())
            return True
        return False

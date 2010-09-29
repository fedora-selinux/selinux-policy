import sys
import cairo
import gobject
import gtk
    

class TutorialTextEditor:

    def on_window_destroy(self, widget, data=None):
        gtk.main_quit()

    def on_show_me_clicked(self, widget):
        pass
     
    def __init__(self):
    
        self.RECT_SIZE = 30
        builder = gtk.Builder()
        builder.add_from_file("/usr/share/setroubleshoot/gui/browser.glade") 
        
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

        self.add_row("green", 100, "smbd should have access to /bin/bash", "/bin/bash is mislabeled", "change the label of /bin/bash to samba_share_t")
        self.add_row("green", 80, "smbd should have access to /bin/bash", "/bin/bash is mislabeled", "change the label of /bin/bash to samba_share_t")
        self.add_row("green", 50, "smbd should have access to /bin/bash", "/bin/bash is mislabeled", "change the label of /bin/bash to samba_share_t")
        self.add_row("yellow", 30, "smbd should have access to /bin/bash", "/bin/bash is mislabeled", "change the label of /bin/bash to samba_share_t")
        self.add_row("yellow", 30, "smbd should have access to /bin/bash", "/bin/bash is mislabeled", "change the label of /bin/bash to samba_share_t")
        self.add_row("red", 10, "smbd should have access to /bin/bash", "/bin/bash is mislabeled", "change the label of /bin/bash to samba_share_t")

        builder.connect_signals(self)       

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


    
if __name__ == "__main__":
    editor = TutorialTextEditor()
    editor.window.show()
    gtk.main()


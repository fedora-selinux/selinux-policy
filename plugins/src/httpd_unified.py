#
# Authors: Dan Walsh <dwalsh@redhat.com>
#
# Copyright (C) 2006 Red Hat, Inc.
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
translation=gettext.translation('setroubleshoot-plugins', fallback=True)
_=translation.ugettext
import selinux

from setroubleshoot.Plugin import Plugin

class plugin(Plugin):
    summary = _('''
    SELinux prevented httpd $ACCESS access to http files.
    ''')
    
    problem_description = _('''
    SELinux prevented httpd $ACCESS access to http files.

    Ordinarily httpd is allowed full access to all files labeled with http file
    context.  This machine has a tightened security policy with the $BOOLEAN
    turned off,  This requires explicit labeling of all files.  If a file is
    a cgi script it needs to be labeled with httpd_TYPE_script_exec_t in order
    to be executed.  If it is read only content, it needs to be labeled
    httpd_TYPE_content_t, it is writable content. it needs to be labeled
    httpd_TYPE_script_rw_t or httpd_TYPE_script_ra_t. You can use the
    chcon command to change these context.  Please refer to the man page
    "man httpd_selinux" or 
    <a href="http://fedora.redhat.com/docs/selinux-apache-fc3">FAQ</a>
    "TYPE" refers toi one of "sys", "user" or "staff" or potentially other
    script types.
    ''')
    
    fix_description = _('''
    Changing the "$BOOLEAN" boolean to true will allow this access:
    "setsebool -P $BOOLEAN=1"
    ''')
    
    fix_cmd = 'setsebool -P $BOOLEAN=1'

    if_text = _("you want to allow httpd to execute cgi scripts and to unify HTTPD handling of all content files.")
    then_text = _("you must tell SELinux about this by enabling the 'httpd_unified' and 'http_enable_cgi' booleans")
    do_text = "# setsebool -P httpd_unified=1 httpd_enable_cgi=1"

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(8)

    def analyze(self, avc):
        if avc.matches_source_types("httpd_t httpd_.*_script_t") and \
           avc.matches_target_types("httpd_.*t") and \
           (avc.tclass == "file" or avc.tclass == "dir") and \
           ( not selinux.security_get_boolean_active("httpd_unified")) and \
           ( not selinux.security_get_boolean_active("httpd_enable_cgi")):
            return self.report()

        return None

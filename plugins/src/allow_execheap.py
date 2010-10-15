#
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
translation=gettext.translation('setroubleshoot-plugins', fallback=True)
_=translation.ugettext

from setroubleshoot.util import *
from setroubleshoot.Plugin import Plugin

class plugin(Plugin):
    summary =_('''
    SELinux is preventing $SOURCE_PATH from changing the access
    protection of memory on the heap.
    ''')
    
    problem_description = _('''
    The $SOURCE application attempted to change the access protection of memory on
    the heap (e.g., allocated using malloc).  This is a potential security
    problem.  Applications should not be doing this. Applications are
    sometimes coded incorrectly and request this permission.  The
    <a href="http://people.redhat.com/drepper/selinux-mem.html">SELinux Memory Protection Tests</a>
    web page explains how to remove this requirement.  If $SOURCE does not work and
    you need it to work, you can configure SELinux temporarily to allow
    this access until the application is fixed. Please file a bug
    report against this package.
    ''')

    fix_description = _('''
    If you want $SOURCE to continue, you must turn on the
    $BOOLEAN boolean.  Note: This boolean will affect all applications
    on the system.
    ''')
    
    if_text = _("you do not think $SOURCE_PATH should need to map heap memory that is both writable and executable.")
    then_text = _("you need to report a bug. This is a potentially dangerous access.")
    do_text = _("Contact your security administrator and report this issue.")

    def __init__(self):
        Plugin.__init__(self, __name__)
        
    def analyze(self, avc):
        if avc.has_any_access_in(['execheap']):
            return self.report()
        else:
            return None





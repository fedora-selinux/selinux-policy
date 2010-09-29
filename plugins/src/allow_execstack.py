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
    SELinux is preventing $SOURCE_PATH from making the program stack executable.
    ''')
    
    problem_description = _('''
    The $SOURCE application attempted to make its stack
    executable.  This is a potential security problem.  This should
    never ever be necessary. Stack memory is not executable on most
    OSes these days and this will not change. Executable stack memory
    is one of the biggest security problems. An execstack error might
    in fact be most likely raised by malicious code. Applications are
    sometimes coded incorrectly and request this permission.  The
    <a href="http://people.redhat.com/drepper/selinux-mem.html">SELinux Memory Protection Tests</a>
    web page explains how to remove this requirement.  If $SOURCE does not
    work and you need it to work, you can configure SELinux
    temporarily to allow this access until the application is fixed. Please 
file a bug report.
    ''')
    
    fix_description = _('''
    Sometimes a library is accidentally marked with the execstack flag,
    if you find a library with this flag you can clear it with the
    execstack -c LIBRARY_PATH.  Then retry your application.  If the
    app continues to not work, you can turn the flag back on with
    execstack -s LIBRARY_PATH.  Otherwise, if you trust $SOURCE to
    run correctly, you can change the context of the executable to
    execmem_exec_t. "chcon -t execmem_exec_t
    '$SOURCE_PATH'"
    You must also change the default file context files on the system in order to preserve them even on a full relabel.  "semanage fcontext -a -t execmem_exec_t '$FIX_SOURCE_PATH'"
    
    ''')

    fix_cmd = "chcon -t execmem_exec_t '$SOURCE_PATH'"

    if_text = _("you do not think $SOURCE_PATH should need to map stack memory that is both writable and executable.")
    then_text = _("you need to report a bug. This is a potentially dangerous access.")
    do_text = _("Contact your security administrator and report this issue.")

    def __init__(self):
        Plugin.__init__(self,__name__)

    def analyze(self, avc):
        if avc.matches_source_types(['unconfined_t']) and \
           avc.has_any_access_in(['execstack']):
            # MATCH
            return self.report()
        else:
            return None


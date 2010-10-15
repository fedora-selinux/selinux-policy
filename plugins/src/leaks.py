#
# Copyright (C) 2009 Red Hat, Inc.
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
    SELinux is preventing $SOURCE_PATH access to a leaked $TARGET_PATH file descriptor.
    ''')
    
    problem_description = _('''
    SELinux denied access requested by the $SOURCE command. It looks like this is either a leaked descriptor or $SOURCE output was redirected to a file it is not allowed to access.  Leaks usually can be ignored since SELinux is just closing the leak and reporting the error.  The application does not use the descriptor, so it will run properly.  If this is a redirection, you will not get output in the $TARGET_PATH.  You should generate a bugzilla on selinux-policy, and it will get routed to the appropriate package.  You can safely ignore this avc.
    ''')
    
    fix_description = _('''
    You can generate a local policy module to allow this
    access - see <a href="http://docs.fedoraproject.org/selinux-faq-fc5/#id2961385">FAQ</a>
    ''')

    fix_cmd = ""

    if_text = _('you want to ignore $SOURCE_PATH trying to $ACCESS access the $TARGET_PATH $TARGET_CLASS, because you believe it should not need this access.')
    then_text = _('You should report this as a bug.  \nYou can generate a local policy module to dontaudit this access.')
    do_text = _("""# grep $SOURCE_PATH /var/log/audit/audit.log | audit2allow -D -M mypol
# semodule -i mypol.pp""")

    def __init__(self):
        Plugin.__init__(self,__name__)
        self.set_priority(1)

    def analyze(self, avc):
        import commands
        if avc.syscall == 'execve':
            if not avc.has_tclass_in(['process', 'capability', 'file']) or \
                    avc.has_any_access_in(['write', 'append']):
            # MATCH
                return self.report()

        return None

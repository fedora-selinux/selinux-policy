
#
# Authors: Dan Walsh <dwalsh@redhat.com>
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

from setroubleshoot.Plugin import Plugin

class plugin(Plugin):
    summary = _('''SELinux is preventing $SOURCE_PATH "$ACCESS" access.''')

    problem_description = _('''

    SELinux denied access requested by $SOURCE. It is not
    expected that this access is required by $SOURCE and this access
    may signal an intrusion attempt. It is also possible that the specific
    version or configuration of the application is causing it to require
    additional access.

    ''')

    fix_description = _('''
    You can generate a local policy module to allow this
    access - see <a href="http://docs.fedoraproject.org/selinux-faq-fc5/#id2961385">FAQ</a>

    Please file a bug report.
    ''')

    if_text = _('you want to allow $SOURCE_PATH to have $ACCESS access on the $TARGET_PATH $TARGET_CLASS by default.')
    then_text = _('You should report this as a bug.\nYou can generate a local policy module to allow this access.')
    do_text = _("""Allow this access for now by executing:
# grep $SOURCE_PATH /var/log/audit/audit.log | audit2allow -M mypol
# semodule -i mypol.pp""")

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(1)
        self.report_bug = True

    def analyze(self, avc):
        if avc.tpath:
            summary = self.summary + " on " + avc.tpath + "."
        else:
            summary = self.summary + "."

        return self.report()

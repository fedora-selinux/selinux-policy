# @author Dan Walsh <dwalsh@redhat.com>
# @author Eric Paris <eparis@redhat.com>
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
import re
import os

class plugin(Plugin):
    summary =_('''
    SELinux has prevented wine from performing an unsafe memory operation.
    ''')

    problem_description = _('''
SELinux denied an operation requested by wine-preloader, a program used
to run Windows applications under Linux.  This program is known to use
an unsafe operation on system memory but so are a number of
malware/exploit programs which masquerade as wine.  If you were
attempting to run a Windows program your only choices are to allow this
operation and reduce your system security against such malware or to
refrain from running Windows applications under Linux.  If you were not
attempting to run a Windows application this indicates you are likely
being attacked by some for of malware or program trying to exploit your
system for nefarious purposes.

Please refer to 

http://wiki.winehq.org/PreloaderPageZeroProblem

Which outlines the other problems wine encounters due to its unsafe use
of memory and solutions to those problems.

    ''')

    fix_description = _('''
If you decide to continue to run the program in question you will need
to allow this operation.  This can be done on the command line by
executing:

# setsebool -P mmap_low_allowed 1
''')

    fix_cmd = "/usr/sbin/setsebool -P mmap_low_allowed 1"

    if_text=_("you want to ignore this AVC because it is dangerous and your wine applications are working correctly.")
    then_text = _("you must tell SELinux about this by enabling the wine_mmap_zero_ignore boolean.")
    do_text = "# setsebool -P wine_mmap_zero_ignore 1"

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.fixable=True
        self.button_text=_("Turn off memory protection")

    def analyze(self, avc):
        if avc.has_any_access_in(['mmap_zero']) and \
                avc.matches_source_types(['.*wine_t']) and \
                os.stat(avc.spath).st_uid == 0:            

            # MATCH
            return self.report()
        return None

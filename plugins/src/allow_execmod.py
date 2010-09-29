#
# Copyright (C) 2006,2009 Red Hat, Inc.
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
    SELinux is preventing $SOURCE_PATH from loading $TARGET_PATH which requires text relocation.
    ''')
    
    problem_description = _('''
    The $SOURCE application attempted to load $TARGET_PATH which
    requires text relocation.  This is a potential security problem.
    Most libraries do not need this permission. Libraries are
    sometimes coded incorrectly and request this permission.  The
    <a href="http://people.redhat.com/drepper/selinux-mem.html">SELinux Memory Protection Tests</a>
    web page explains how to remove this requirement.  You can configure
    SELinux temporarily to allow $TARGET_PATH to use relocation as a
    workaround, until the library is fixed. Please file a 
bug report.
    ''')
    
    unsafe_problem_description = _('''
    The $SOURCE application attempted to load $TARGET_PATH which
    requires text relocation.  This is a potential security problem.
    Most libraries should not need this permission.   The   
    <a href="http://people.redhat.com/drepper/selinux-mem.html">
    SELinux Memory Protection Tests</a>
    web page explains this check.  This tool examined the library and it looks 
    like it was built correctly. So setroubleshoot can not determine if this 
    application is compromized or not.  This could be a serious issue. Your 
    system may very well be compromised.

    Contact your security administrator and report this issue.

    ''')
    
    unsafe_fix_description = "Contact your security administrator and report this issue." 

    fix_description = _('''
    If you trust $TARGET_PATH to run correctly, you can change the
    file context to textrel_shlib_t. "chcon -t textrel_shlib_t
    '$TARGET_PATH'"
    You must also change the default file context files on the system in order to preserve them even on a full relabel.  "semanage fcontext -a -t textrel_shlib_t '$FIX_TARGET_PATH'"
    
    ''')

    then_text = "You need to change the label on '$FIX_TARGET_PATH'"
    do_text = """# semanage fcontext -a -t textrel_shlib_t '$FIX_TARGET_PATH'
# restorecon -v '$FIX_TARGET_PATH'"""

    def __init__(self):
        Plugin.__init__(self,__name__)
        self.set_priority(10)

    def analyze(self, avc):
        import commands
        if avc.has_any_access_in(['execmod']):
            # MATCH
            if (commands.getstatusoutput("eu-readelf -d %s | fgrep -q TEXTREL" % avc.tpath)[0] == 1):
                return self.report(("unsafe"))

            return self.report()
        return None

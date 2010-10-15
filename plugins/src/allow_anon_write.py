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

from setroubleshoot.util import *
from setroubleshoot.Plugin import Plugin

class plugin(Plugin):
    summary =_('''
    SELinux policy is preventing an httpd script from writing to a public
    directory.
    ''')

    problem_description = _('''
    SELinux policy is preventing an httpd script from writing to a public
    directory.  If httpd is not setup to write to public directories, this
    could signal an intrusion attempt.
    ''')

    fix_description = _('''
    If httpd scripts should be allowed to write to public directories you need to turn on the $BOOLEAN boolean and change the file context of the public directory to public_content_rw_t.  Read the httpd_selinux
    man page for further information:
    "setsebool -P $BOOLEAN=1; chcon -t public_content_rw_t <path>"
    You must also change the default file context files on the system in order to preserve them even on a full relabel.  "semanage fcontext -a -t public_content_rw_t <path>"
    ''')
    if_text = _("you want to allow $SOURCE_PATH to be able to write to shared public content")
    then_text = _("you need to change the label on $TARGET_PATH to public_content_rw_t, and potentially turn on the allow_httpd_sys_script_anon_write boolean.")

    def get_do_text(self, avc, args):
        do_text = """# semanage fcontext -a -t public_content_rw_t $TARGET_PATH
# restorecon -R -v $TARGET_PATH
# setsebool -P %s %s""" % args
        return do_text

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.level="green"

    def analyze(self, avc):
        if avc.matches_target_types(['public_content_t']) and \
                avc.all_accesses_are_in(avc.create_file_perms):

            if avc.matches_source_types(['httpd_t']):
                return self.report(('allow_httpd_anon_write', "1"))

            if avc.matches_source_types(['httpd_sys_script_t']):
                return self.report(('allow_httpd_sys_script_anon_write', "1"))

            if avc.matches_source_types(['ftpd_t']):
                return self.report(('allow_ftpd_anon_write', "1"))

            if avc.matches_source_types(['nfsd_t']):
                return self.report(('allow_nfsd_anon_write', "1"))

            if avc.matches_source_types(['rsync_t']):
                return self.report(('allow_rsync_anon_write', "1"))

            if avc.matches_source_types(['smbd_t']):
                return self.report(('allow_smbd_anon_write', "1"))

        return None

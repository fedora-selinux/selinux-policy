# Authors: John Dennis <jdennis@redhat.com>
#          Thomas Liu <tliu@redhat.com>
#          Dan Walsh <dwalsh@redhat.com>
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

from setroubleshoot.signature import *
from setroubleshoot.util import *
from setroubleshoot.log import *

#import sys
#import os.path
import re

#------------------------------------------------------------------------------
class Plugin(object):
    """
    Each plugin object recognizes one or more access denials and
    presents a description of the denial to the user. Optionally,
    the plugin can provide a suggestion for allowing the access
    to the user.

    There are four user visible strings that are part of each Plugin
    subclass (some or all of these can be changed by the plugin author):
     * summary: summary of the denial
     * problem_description: detailed description of the denial
     * fix_description: description of how to allow the denied access
     * fix_cmd: command that can be used to allow the access

    All of the strings will have a standard set of substitutions performed.
    Each keyword (proceeded by a '$' will be replace by a string) - see
    http://docs.python.org/lib/node109.html for more information. The
    keywords are:
     * $SOURCE_TYPE - type for the source of the avc (usually the
       process performing the operation).
     * $TARGET_TYPE - type for the target of the avc (the type of
       the object).
     * $SOURCE_PATH - source of the executable (from the exe or comm
       field of the exe). A full path is not always available.
     * $TARGET_PATH - path for the target object. A full path is not
       always available.
     * $TARGET_DIR - path of the containing directory for TARGET_PATH.
       Essentially os.path.dirname($TARGET_PATH)
     * $TARGET_CLASS - the object class for the target.
     * $PERMS - the permissions denied.
     * $SOURCE_PACKAGE - name of the package which contains the
       executable (from $SOURCE_PATH).
     * $PORT_NUMBER - the port number for the connection denied.
    Additional subtitutions can be added with set_template_substitutions.

    You can also optional pass the name for a single boolean which will be
    used to set the $BOOLEAN subtitution into Plugin.__init__.
o
    You can also set the level, of the alert, if the plugin believes discovers 
    a signature of an attack, the level should be set to red
    * level:  Defines the level of the alert
    ** yellow default
    ** red Indicates troubleshooter believes machine is being attacked
    ** green Indicates a configuration issue.  Browser will not display Report Bug button
    ** white Tells the troubleshooter to ignore the AVC
        """
    summary = ""
    problem_description = ""
    if_text = _('you want to allow $SOURCE_BASE_PATH to have $ACCESS access on the $TARGET_BASE_PATH $TARGET_CLASS')
    then_text = "No default"
    do_text = "No default"
        
    def __init__(self, name):
        self.analysis_id = re.sub(r'^plugins\.', '', name)
        self.priority = 10
        self.level = "yellow"
        self.fixable = False
        self.button_text = ""
        self.report_bug = False
        
    def get_if_text(self, avc, args):
        return self.if_text

    def get_then_text(self, avc, args):
        return self.then_text

    def get_do_text(self, avc, args):
        return self.do_text

    def get_fix_cmd(self, avc, args):
        return self.fix_cmd

    def get_if_text(self, avc, args):
        return self.if_text

    def report(self,args=()):
        """
        Report a denial and solution to the fault server.
        """

        return SEPlugin(self.analysis_id, args)
        
    def analyze(self, avc):
        return False

    def set_priority(self, priority):
        self.priority = priority
        
    def get_priority(self):
        return self.priority 
        
        

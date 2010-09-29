#!/usr/bin/python
import selinux
import sys
def setroubleshoot_print( se_plugin ):
        rec = "<setroubleshoot>\n"
        rec += "<summary>"
        rec += se_plugin.summary
        rec += "</summary>\n"
        rec += "<problem>"
        rec += se_plugin.problem_description
        rec += "</problem>\n"
        rec += "<fix>"
        rec += se_plugin.fix_description
        rec += "</fix>\n"
        rec += "</setroubleshoot>"
        return rec
    
__all__ = ['RunFaultServer',
           'get_host_database',
           'send_alert_notification',
          ]
from setroubleshoot.config import get_config
import gettext
gettext.install(domain    = get_config('general', 'i18n_text_domain'),
                localedir = get_config('general', 'i18n_locale_dir'),
                unicode   = False,
                codeset   = get_config('general', 'i18n_encoding'))

from setroubleshoot.util import *
se_plugins = {} 
plugins = load_plugins()
for p in plugins:
    se_plugins[p.analysis_id.split(".")[1]] = p

fd = open("/usr/share/system-config-selinux/selinux.tbl")
booll = fd.readlines()
fd.close()
booldict={}
for l in booll:
    temp = l.split(' _("')
    if len(temp) > 1:
        booldict[temp[0].strip()] = [ temp[1].strip('")'), temp[2].strip('")\n') ]

booleans = selinux.security_get_boolean_names()
for b in booleans[1]:
    try:
        se_plugins[p.analysis_id.split(".")[1]] = p
        rec = "<boolean>\n<name>%s</name>\n" % b
        if b in booldict:
            rec += "<description>%s</description>\n" % booldict[b][1]
            rec += "<category>%s</category>\n" % booldict[b][0]
        if b in se_plugins:
            rec += setroubleshoot_print(se_plugins[b])
        rec += "</boolean>"
        print rec
    except:
        raise
        pass


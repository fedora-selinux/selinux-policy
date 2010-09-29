#/usr/bin/env python

# Author: Thomas Liu <tliu@redhat.com>
import yum
import gettext
from setroubleshoot.config import parse_config_setting, get_config
gettext.install(domain    = get_config('general', 'i18n_text_domain'),
                localedir = get_config('general', 'i18n_locale_dir'))

installed = []
try:
    yb = yum.YumBase()
    yb.conf.cache = True
    installed = yb.rpmdb.searchNevra('selinux-policy')
    if installed:
        for pkg in sorted(installed):
            if pkg.name == 'selinux-policy':
                print _("current: %s ") % pkg.printVer()
    try:
        pl = yb.doPackageLists(patterns=['selinux-policy'])
    except yum.Errors.RepoError, msg:
        yb.conf.cache = False
        pl = yb.doPackageLists(patterns=['selinux-policy'])

    if pl.available:
        for pkg in sorted(pl.available):
            print _("newer: %s ") % pkg.printVer()
            

except yum.Errors.RepoError, msg:
    print "error: ", str(msg)

except yum.Errors.ConfigError, msg:
    print "error: ", str(msg)

except TypeError, msg:
    print "error: ", str(msg)
except Exception, e:
    print "error: " + str(e)


print "done"

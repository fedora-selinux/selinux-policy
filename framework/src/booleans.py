#!/usr/bin/python
import seobject
for i in seobject.booleans_dict:
    desc = seobject.booleans_dict[i][2]
#    print "If you want to " + desc[0].lower() + desc[1:]
#    print "Then you must tell SELinux about this by enabling the %s boolean" % i
#    print "Do # setsebool -P %s 1 " % i
#    print "======================================================================"
    print desc[0].lower() + desc[1:]


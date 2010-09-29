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

# What Dan thinks is unique id:
# tclass
# access
# tcontext
# scontext
# comm
# name

__all__ = ['XMLNotFoundException',
           'AVC',
           'SignatureMatch',
           'SEFilter',
           'SEFaultSignature',
           'SEFaultSignatureInfo',
           'SEFaultSignatureSet',
           'SEFaultSolution',
           'SEFaultSignatureUser',
           'SEEnvironment',
           'SEDatabaseProperties',
           'AvcContext',
           'GetElements',
           'SEFaultUserInfo',
           'SEFaultUserSet',
           'SEEmailRecipient',
           'SEEmailRecipientSet',

           'FILTER_NEVER',
           'FILTER_TILL_FIX',
           'FILTER_TILL_RPM_CHANGE',
           'FILTER_TILL_POLICY_CHANGE',
           'FILTER_ALWAYS',
           'FILTER_DAY',
           'FILTER_WEEK',
           'FILTER_AFTER_FIRST',
           'FILTER_TILL_DATE',
           'filter_text'
           ]

import libuser
global VALID_EXES
INVALID_EXES=libuser.get_user_shells() + [ "/usr/bin/perl" , "/usr/bin/python" ]

from setroubleshoot.config import get_config
from setroubleshoot.errcode import *
from setroubleshoot.util import *
from setroubleshoot.log import *
from setroubleshoot.util import *
import setroubleshoot.uuid as uuid

import selinux
import sys
import re
import string
from types import *
import libxml2
import exceptions

i18n_encoding = get_config('general', 'i18n_encoding')

# Don't reuse the numeric values!
FILTER_NEVER              = 0
FILTER_TILL_FIX           = 1
FILTER_TILL_RPM_CHANGE    = 2
FILTER_TILL_POLICY_CHANGE = 3
FILTER_ALWAYS             = 4
FILTER_DAY                = 5
FILTER_WEEK               = 6
FILTER_AFTER_FIRST        = 8

# internal value so keep it well away from the other numerical values
FILTER_TILL_DATE = 1000

instance_path_re = re.compile('^(\w+):\[([^\]]*)\]')


filter_text = {
    FILTER_NEVER              : _("Never Ignore"),
    FILTER_TILL_FIX           : _("Ignore Until Fix Released"),
    FILTER_TILL_RPM_CHANGE    : _("Ignore Until RPM Updated"),
    FILTER_TILL_POLICY_CHANGE : _("Ignore Until Policy Updated"),
    FILTER_ALWAYS             : _("Ignore Always"),
    FILTER_DAY                : _("Ignore For 1 Day"),
    FILTER_WEEK               : _("Ignore For 1 Week"),
    FILTER_AFTER_FIRST        : _("Ignore After First Alert"),
    }

map_filter_value_to_name = {
    FILTER_NEVER              : 'never',
    FILTER_TILL_FIX           : 'till_fix',
    FILTER_TILL_RPM_CHANGE    : 'till_rpm_change',
    FILTER_TILL_POLICY_CHANGE : 'till_policy_change',
    FILTER_ALWAYS             : 'always',
    FILTER_DAY                : 'day',
    FILTER_WEEK               : 'week',
    FILTER_AFTER_FIRST        : 'after_first',
    }

map_filter_name_to_value = {
    'never'                   : FILTER_NEVER,
    'till_fix'                : FILTER_TILL_FIX,
    'till_rpm_change'         : FILTER_TILL_RPM_CHANGE,
    'till_policy_change'      : FILTER_TILL_POLICY_CHANGE,
    'always'                  : FILTER_ALWAYS,
    'day'                     : FILTER_DAY,
    'week'                    : FILTER_WEEK,
    'after_first'             : FILTER_AFTER_FIRST,
    }

AvcContextAttrs = {
    'user'      : {'XMLForm'     : 'attribute'},
    'role'      : {'XMLForm'     : 'attribute'},
    'type'      : {'XMLForm'     : 'attribute'},
    'mls'       : {'XMLForm'     : 'attribute'},
}

AVCAttrs = {
    'a0'	: {'description' : "alphanumeric, the first argument to a syscall",
                   'XMLForm'     : 'attribute'},
    'a1'	: {'description' : "alphanumeric, the second arguments to a syscall",
                   'XMLForm'     : 'attribute'},
    'a2'	: {'description' : "alphanumeric, the third argument to a syscall",
                   'XMLForm'     : 'attribute'},
    'a3'	: {'description' : "alphanumeric, the fourth argument to a syscall",
                   'XMLForm'     : 'attribute'},
    'access'    : {'description' : "list, list of operations which triggered the AVC",
                   'XMLForm'     : 'element',
                   'list'        : {'name' : 'operation', 'text':None}},
    'acct'	: {'description' : "alphanumeric, a user's account name",
                   'XMLForm'     : 'attribute'},
    'addr'	: {'description' : "the remote address that the user is connecting from",
                   'XMLForm'     : 'attribute'},
    'arch'	: {'description' : "numeric, the elf architecture flags",
                   'XMLForm'     : 'attribute'},
    'auid'	: {'description' : "numeric, login user id",
                   'XMLForm'     : 'attribute'},
    'comm'	: {'description' : "alphanumeric, command line program name",
                   'XMLForm'     : 'attribute'},
    'cwd'	: {'description' : "path name, the current working directory",
                   'XMLForm'     : 'attribute'},
    'dest'	: {'description' : "numeric, port number",
                   'XMLForm'     : 'attribute'},
    'dev'	: {'description' : "numeric, in path records, major and minor for device",
                   'XMLForm'     : 'attribute'},
    'dev'	: {'description' : "in avc records, device name as found in /dev",
                   'XMLForm'     : 'attribute'},
    'egid'	: {'description' : "numeric, effective group id",
                   'XMLForm'     : 'attribute'},
    'euid'	: {'description' : "numeric, effective user id",
                   'XMLForm'     : 'attribute'},
    'exe'	: {'description' : "path name, executable name",
                   'XMLForm'     : 'attribute'},
    'exit'	: {'description' : "numeric, syscall exit code",
                   'XMLForm'     : 'attribute'},
    'file'	: {'description' : "file name",
                   'XMLForm'     : 'attribute'},
    'flags'	: {'description' : "numeric, file system namei flags",
                   'XMLForm'     : 'attribute'},
    'format'	: {'description' : "alphanumeric, audit log's format",
                   'XMLForm'     : 'attribute'},
    'fsgid'	: {'description' : "numeric, file system group id",
                   'XMLForm'     : 'attribute'},
    'fsuid'	: {'description' : "numeric, file system user id",
                   'XMLForm'     : 'attribute'},
    'gid'	: {'description' : "numeric, group id",
                   'XMLForm'     : 'attribute'},
    'hostname'	: {'description' : "alphanumeric, the hostname that the user is connecting from",
                   'XMLForm'     : 'attribute'},
    'id'	: {'description' : "numeric, during account changes, the user id of the account",
                   'XMLForm'     : 'attribute'},
    'igid'	: {'description' : "numeric, ipc object's group id",
                   'XMLForm'     : 'attribute'},
    'inode'	: {'description' : "numeric, inode number",
                   'XMLForm'     : 'attribute'},
    'inode_gid'	: {'description' : "numeric, group id of the inode's owner",
                   'XMLForm'     : 'attribute'},
    'inode_uid'	: {'description' : "numeric, user id of the inode's owner",
                   'XMLForm'     : 'attribute'},
    'item'	: {'description' : "numeric, which item is being recorded",
                   'XMLForm'     : 'attribute'},
    'items'	: {'description' : "numeric, the number of path records in the event",
                   'XMLForm'     : 'attribute'},
    'iuid'	: {'description' : "numeric, ipc object's user id",
                   'XMLForm'     : 'attribute'},
    'list'	: {'description' : "numeric, the audit system's filter list number",
                   'XMLForm'     : 'attribute'},
    'mode'	: {'description' : "numeric, mode flags on a file",
                   'XMLForm'     : 'attribute'},
    'msg'	: {'description' : "alphanumeric, the payload of the audit record",
                   'XMLForm'     : 'attribute'},
    'nargs'	: {'description' : "numeric, the number of arguments to a socket call",
                   'XMLForm'     : 'attribute'},
    'name'	: {'description' : "file name in avcs",
                   'XMLForm'     : 'attribute'},
    'obj'	: {'description' : "alphanumeric, lspp object context string",
                   'XMLForm'     : 'attribute'},
    'ogid'	: {'description' : "numeric, file owner group id",
                   'XMLForm'     : 'attribute'},
    'old'	: {'description' : "numeric, old audit_enabled, audit_backlog, or audit_failure value",
                   'XMLForm'     : 'attribute'},
    'old_prom'	: {'description' : "numeric, network promiscuity flag",
                   'XMLForm'     : 'attribute'},
    'op'	: {'description' : "alphanumeric, the operation being performed that is audited",
                   'XMLForm'     : 'attribute'},
    'ouid'	: {'description' : "numeric, file owner user id",
                   'XMLForm'     : 'attribute'},
    'parent'	: {'description' : "numeric, the inode number of the parent file",
                   'XMLForm'     : 'attribute'},
    'path'	: {'description' : "file system path name",
                   'XMLForm'     : 'attribute'},
    'perm'	: {'description' : "numeric, the file permission being used",
                   'XMLForm'     : 'attribute'},
    'perm_mask'	: {'description' : "numeric, file permission audit mask that triggered a watch event",
                   'XMLForm'     : 'attribute'},
    'pid'	: {'description' : "numeric, process id",
                   'XMLForm'     : 'attribute'},
    'prom'	: {'description' : "numeric, network promiscuity flag",
                   'XMLForm'     : 'attribute'},
    'qbytes'	: {'description' : "numeric, ipc objects quantity of bytes",
                   'XMLForm'     : 'attribute'},
    'range'	: {'description' : "alphanumeric, user's SE Linux range",
                   'XMLForm'     : 'attribute'},
    'rdev'	: {'description' : "numeric, the device identifier (special files only)",
                   'XMLForm'     : 'attribute'},
    'result'	: {'description' : "alphanumeric, result of the audited operation (success/fail)",
                   'XMLForm'     : 'attribute'},
    'role'	: {'description' : "alphanumeric, user's SE linux role",
                   'XMLForm'     : 'attribute'},
    'saddr'	: {'description' : "alphanumeric, socket address",
                   'XMLForm'     : 'attribute'},
    'sauid'	: {'description' : "numeric, sending login user id",
                   'XMLForm'     : 'attribute'},
    'scontext'	: {'description' : "alphanumeric, the subject's context string",
                   'XMLForm'     : 'element',  'class':{'name':'AvcContext'}},
    'seuser'	: {'description' : "alphanumeric, user's SE Linux user acct",
                   'XMLForm'     : 'attribute'},
    'sgid'	: {'description' : "numeric, set group id",
                   'XMLForm'     : 'attribute'},
    'spid'	: {'description' : "numeric, sending process id",
                   'XMLForm'     : 'attribute'},
    'src'	: {'description' : "numeric, port number",
                   'XMLForm'     : 'attribute'},
    'subj'	: {'description' : "alphanumeric, lspp subject's context string",
                   'XMLForm'     : 'attribute'},
    'success'	: {'description' : "alphanumeric, whether the syscall was successful or not",
                   'XMLForm'     : 'attribute'},
    'suid'	: {'description' : "numeric, sending user id",
                   'XMLForm'     : 'attribute'},
    'syscall'	: {'description' : "numeric, the syscall number in effect when the event occurred",
                   'XMLForm'     : 'attribute'},
    'tclass'	: {'description' : "alphanumeric, target's object classification",
                   'XMLForm'     : 'attribute'},
    'tcontext'	: {'description' : "alphanumeric, the target's or object's context string",
                   'XMLForm'     : 'element',  'class':{'name':'AvcContext'}},
    'terminal'	: {'description' : "alphanumeric, terminal name the user is running programs on",
                   'XMLForm'     : 'attribute'},
    'tty'	: {'description' : "alphanumeric, tty interface that the user is running programs on",
                   'XMLForm'     : 'attribute'},
    'type'	: {'description' : "alphanumeric, the audit record's type",
                   'XMLForm'     : 'attribute'},
    'uid'	: {'description' : "numeric, user id",
                   'XMLForm'     : 'attribute'},
    'user'	: {'description' : "alphanumeric, account the user claims to be prior to authentication",
                   'XMLForm'     : 'attribute'},
    'ver'	: {'description' : "numeric, audit daemon's version number",
                   'XMLForm'     : 'attribute'},
    'watch'	: {'description' : "the file name in a watch record",
                   'XMLForm'     : 'attribute'},
}


SEFaultSignatureAttrs = {
    'version'          : {'XMLForm':'attribute','default':lambda: '1.0'                       },
    'analysis_id'      : {'XMLForm':'element'                                                 },
    'avc_list'         : {'XMLForm':'element',  'list' :{'name':'avc', 'class':{'name':'AVC'}}},
    'environment'      : {'XMLForm':'element',  'class':{'name':'SEEnvironment'}              },
    'object_path'      : {'XMLForm':'element'                                                 },
    'rpm'              : {'XMLForm':'element'                                                 },
    'host'             : {'XMLForm':'element'                                                 },
    }

SEFaultSignatureSetAttrs = {
    'version'          : {'XMLForm':'attribute','default':lambda: '1.2'                       },
    'users'            : {'XMLForm':'element', 'class':{'name':'SEFaultUserSet'}, 'default': lambda: SEFaultUserSet()},
    'signature_list'   : {'XMLForm':'element',
                          'list'   :{'name':'siginfo', 'class': {'name':'SEFaultSignatureInfo'}},
                          'default': lambda: []                                        },
    }

SEFilterAttrs = {
    'filter_type'      : {'XMLForm':'element', 'class': {'name':'int', 'is_xml':False}, 'default':lambda: FILTER_NEVER},
    'till_date'        : {'XMLForm':'element'},
    'rpm_watch_list'   : {'XMLForm':'element','list':{'name':'rpm', 'text':None}},
    'count'            : {'XMLForm':'element', 'class': {'name':'int', 'is_xml':False}, 'default':lambda: 0},
}

SEFaultSignatureUserAttrs = {
    'username'         : {'XMLForm':'attribute'},
    'seen_flag'        : {'XMLForm':'attribute', 'class': {'name':'boolean', 'is_xml':False}, 'default': lambda: False},
    'delete_flag'      : {'XMLForm':'attribute', 'class': {'name':'boolean', 'is_xml':False}, 'default': lambda: False},
    'filter'           : {'XMLForm':'element', 'class' : {'name':'SEFilter'}, 'default': lambda: SEFilter()},
    }

SEFaultSignatureInfoAttrs = {
    'analysis_id'      : {'XMLForm':'element'                                                 },
    'sig'              : {'XMLForm':'element', 'class': {'name':'SEFaultSignature'}},
    'solution'         : {'XMLForm':'element', 'class': {'name':'SEFaultSolution'} },
    'first_seen_date'  : {'XMLForm':'element', 'class': {'name':'TimeStamp', 'is_xml':False}},
    'last_seen_date'   : {'XMLForm':'element', 'class': {'name':'TimeStamp', 'is_xml':False}},
    'report_count'     : {'XMLForm':'element', 'class': {'name':'int', 'is_xml':False}, 'default':lambda: 0},
    'local_id'         : {'XMLForm':'element'},
    'category'         : {'XMLForm':'element'                                    },
    'environment'      : {'XMLForm':'element',  'class':{'name':'SEEnvironment'}              },
    'avc_list'         : {'XMLForm':'element',  'list' :{'name':'avc', 'class':{'name':'AVC'}}},
    'src_rpm_list'     : {'XMLForm':'element', 'list':{'name':'rpm', 'text':None}, 'default': lambda: []},
    'tgt_rpm_list'     : {'XMLForm':'element', 'list':{'name':'rpm', 'text':None}, 'default': lambda: []},
    'object_path'      : {'XMLForm':'element'                                                 },
    'users'            : {'XMLForm':'element', 'list' : {'name':'user', 'class':{'name':'SEFaultSignatureUser'}},
                          'default': lambda: []},
    'line_numbers'     : {'XMLForm':'element', 'list':{'name':'line', 'class':{'name':'int', 'is_xml':False}}, 'default': lambda: []},

    }

SEFaultSolutionAttrs = {
    'version'             : {'XMLForm':'attribute', 'default': lambda: '1.0'        },
    'summary'             : {'XMLForm':'element'                                    },
    'problem_description' : {'XMLForm':'element',   'is_cdata':True                 },
    'fix_description'     : {'XMLForm':'element',   'is_cdata':True                 },
    'fix_cmd'             : {'XMLForm':'element'                                    },
    'rpm_list'            : {'XMLForm':'element', 'list':{'name':'rpm', 'text':None}, 'default': lambda: []},
    'rpm_version'         : {'XMLForm':'element'                                    },
    'policy_version'      : {'XMLForm':'element'                                    },
    }

SEEnvironmentAttrs = {
    'version'             : {'XMLForm':'attribute','default':lambda: '1.0'                       },
    'platform'            : {'XMLForm':'element'},
    'kernel'              : {'XMLForm':'element'},
    'policy_type'         : {'XMLForm':'element'},
    'policy_rpm'          : {'XMLForm':'element'},
    'enforce'             : {'XMLForm':'element'},
    'selinux_enabled'     : {'XMLForm':'element', 'class': {'name':'boolean', 'is_xml':False}},
    'selinux_mls_enabled' : {'XMLForm':'element', 'class': {'name':'boolean', 'is_xml':False}},
    'policyvers'          : {'XMLForm':'element'},
    'hostname'            : {'XMLForm':'element'},
    'uname'               : {'XMLForm':'element'},
    }

SEDatabasePropertiesAttrs = {
    'name'          : {'XMLForm':'element' },
    'friendly_name' : {'XMLForm':'element' },
    'filepath'      : {'XMLForm':'element' },
    }


SEFaultUserInfoAttrs = {
    'version'            : {'XMLForm':'attribute','default':lambda: '1.0'                       },
    'username'           : {'XMLForm':'attribute'},
    'email_alert'        : {'XMLForm':'element', 'class': {'name':'boolean', 'is_xml':False}, 'default': lambda: False},
    'email_address_list' : {'XMLForm':'element', 'list':{'name':'email_address', 'text':None}, 'default': lambda: []},
    }

SEFaultUserSetAttrs = {
    'version'      : {'XMLForm':'attribute','default':lambda: '1.0' },
    'user_list'    : {'XMLForm':'element',
                      'list'   :{'name':'user', 'class': {'name':'SEFaultUserInfo'}},
                      'default': lambda: [] },
    }


SEEmailRecipientAttrs = {
    'address'          : {'XMLForm':'element'},
    'filter_type'      : {'XMLForm':'element', 'class': {'name':'int', 'is_xml':False}, 'default':lambda: FILTER_AFTER_FIRST},
    }

SEEmailRecipientSetAttrs = {
    'version'         : {'XMLForm':'attribute','default':lambda: '1' },
    'recipient_list'  : {'XMLForm':'element',
                         'list'   :{'name':'recipient', 'class': {'name':'SEEmailRecipient'}},
                         'default': lambda: [] },
    }

def boolean(value):
    'convert value to bool'
    if type(value) == BooleanType:
        return value
    elif type(value == StringType):
        value = value.lower()
        if value in ('t', 'true', '1'):
            return True
        elif value in ('f', 'false', '0'):
            return False
        else:
            raise ValueError("cannot convert (%s) to boolean" % value)
    elif type(value == IntType):
        return bool(value)
    else:
        raise ValueError("cannot convert (%s) to boolean" % value)

# FIXME
class XMLNotFoundException(exceptions.Exception):
    def __init__(self, name, class_name, scope, location):
        self.name = name
        self.class_name = class_name
        self.scope = scope
        self.location = location

    def __str__(self):
        return "element '%s' not found with scope '%s' at node '%s'" % (self.name, self.scope, self.location.name)

def GetElements(xml_node, xpath_expr):
    doc = xml_node.get_doc()
    context = doc.xpathNewContext()
    context.setContextNode(xml_node)
    elements = context.xpathEval(xpath_expr)
    context.xpathFreeContext()
    return elements
    

def BuildSchema(xml_info):
    schema = {}
    names = xml_info.keys()
    names.sort()
    for name in names:
        name_info = xml_info[name]
        if name_info.has_key('list'):
            list_info = name_info['list']
            item_name = list_info['name']
            if list_info.has_key('class'):
                class_info = list_info['class']
                class_name = class_info['name']
                is_xml = class_info.get('is_xml', True)
                schema[name] = eval("BuildSchema(%sAttrs)" % class_name)
            else:
                schema[name] = None
        elif name_info.has_key('class'):
            class_info = name_info['class']
            class_name = class_info['name']
            is_xml = class_info.get('is_xml', True)
            if is_xml:
                schema[name] = eval("BuildSchema(%sAttrs)" % class_name)
            else:
                schema[name] = class_name
        else:
            schema[name] = None
    return schema

def PrintSchema(schema, level):
    indent = '    '

    names = schema.keys()
    names.sort()
    for name in names:
        value = schema[name]
        if type(value) == DictType:
            print '%s%s' % ('    ' * level, name)
            PrintSchema(value, level+1)
        else:
            print '%s%s' % ('    ' * level, name)
    

#------------------------------------------------------------------------

class SignatureMatch(object):
    def __init__(self, siginfo, score):
        self.siginfo = siginfo
        self.score = score


#------------------------------------------------------------------------

class XmlSerialize(object):
    def __init__(self, xml_info, data, obj_name=None, **kwds):
        '''The @data parameter is used to initialize the AVC object, it may
        be passed as:
        * dict with name/value pairs
        * list where each element in the list is a two element list
          containing the pair (name,value)
        * AVC xmlNode (e.g. from a DOM tree)

        In addition named parameters may be passed, e.g. access='read',
        named parameters override contents of the @data parameter.

        Examples:
        # Initializing with named parameters
        a = AVC(access='read',pid='123')

        # Initializing with a dict
        d = {'access':'read','pid':'123'}
        a = AVC(d)

        # Initializing with a list
        l = [['access','read',['pid','123']]
        a = AVC(l)

        # Initializing with an XML node
        avcNode = context.xpathEval("/AVC")
        a = AVC(avcNode[0])

        # Mixed initialization with list and named parameters
        a = AVC(l, targetClass='socket')
        '''

        self.set_default_xml_names(xml_info)
        # Initialize each known class variable to avoid KeyError on access
        for name in self._names:
            name_info = xml_info[name]
            default = name_info.get('default', None)
            if default is not None:
                self.__dict__[name] = default()
            else:
                self.__dict__[name] = None

        if type(data) is DictType:
            for (name, value) in data.items():
                self.__dict__[name] = value
        elif type(data) is ListType or \
             type(data) is TupleType:
            for pair in data:
                name  = pair[0]
                value = pair[1]
                self.__dict__[name] = value
        elif isinstance(data, libxml2.xmlNode):
            self.init_from_xml_node(data, scope='base', obj_name=obj_name)
        for (name, value) in kwds.items():
            self.__dict__[name] = value


    def __str__(self):
        return self.get_xml_text_doc()

    def set_default_xml_names(self, xml_info):
        self._xml_info = xml_info
        self._elements = \
        [x for x in xml_info.keys() if xml_info[x]['XMLForm'] == 'element']
        self._attributes = \
        [x for x in xml_info.keys() if xml_info[x]['XMLForm'] == 'attribute']
        self._names = self._elements + self._attributes

        self._elements.sort()
        self._attributes.sort()
        self._names.sort()


    def get_elements_and_attributes(self):
        elements   = self._elements
        attributes = self._attributes
        return(elements, attributes)


    def get_xml_doc(self, obj_name=None):
        doc = libxml2.newDoc("1.0")
        root = self.get_xml_nodes(doc, obj_name)
        doc.setRootElement(root)
        return doc

    def get_xml_text_doc(self, obj_name=None):
        doc = text_doc = None
        try:
            doc = self.get_xml_doc(obj_name)
            text_doc = doc.serialize(encoding=i18n_encoding, format=1)
        finally:
            if doc is not None:
                doc.freeDoc()
        return text_doc

    def read_xml(self, buf, obj_name=None):
        doc = None
        try:
            try:
                doc = libxml2.parseDoc(buf.strip())
                root_node = doc.getRootElement()
                self.init_from_xml_node(doc, 'sub', obj_name)
            except libxml2.parserError, e:
                log_xml.error("read_xml() libxml2.parserError: %s", e)
                return
        finally:
            if doc is not None:
                doc.freeDoc()

    def read_xml_file(self, xmlfile, obj_name=None):
        doc = None
        try:
            try:
                doc = libxml2.parseFile(xmlfile)
                root_node = doc.getRootElement()
                self.init_from_xml_node(doc, 'sub', obj_name)
            except libxml2.parserError, e:
                log_xml.error("read_xml_file() libxml2.parserError: %s", e)
                return
        finally:
            if doc is not None:
                doc.freeDoc()

    def write_xml(self, obj_name=None, f = None):
        need_to_close = 0
        if f is None:
            f = sys.stdout
        elif type(f) is StringType:
            f = open(f, "w")
            need_to_close = 1
        elif type(f) is FileType:
            pass
        else:
            raise ValueError("bad file parameter %s" % f)

        f.write(self.get_xml_text_doc(obj_name))
        if need_to_close:
            f.close()

    def get_xml_nodes(self, doc, obj_name=None):
        elements, attributes = self.get_elements_and_attributes()
        if obj_name is None:
            obj_name = self.__class__.__name__
        root = libxml2.newNode(obj_name)
        for name in attributes:
            name_info = self._xml_info[name]
            value = self.__dict__[name]
            if value is not None:
                root.setProp(name, str(value))
        for name in elements:
            try:
                name_info = self._xml_info[name]
                is_cdata = name_info.get('is_cdata', False)
                value = self.__dict__[name]
                if value is not None:
                    if name_info.has_key('list'):
                        list_info = name_info['list']
                        item_name = list_info['name']
                        list = root.newChild(None, name, None)
                        if list_info.has_key('class'):
                            class_info = list_info['class']
                            class_name = class_info['name']
                            is_xml = class_info.get('is_xml', True)
                            if is_xml:
                                for item in value:
                                    list.addChild(item.get_xml_nodes(doc, item_name))
                            else:
                                for item in value:
                                    list.newChild(None, item_name, str(item))
                        else:
                            if is_cdata:
                                for item in value:
                                    new_node = list.newChild(None, item_name, None)
                                    new_node.addChild(doc.newCDataBlock(item, len(item)))
                            else:
                                for item in value:
                                    new_node = list.newChild(None, item_name, item)
                    else:
                        if name_info.has_key('class'):
                            class_info = name_info['class']
                            class_name = class_info['name']
                            is_xml = class_info.get('is_xml', True)
                            if is_xml:
                                root.addChild(value.get_xml_nodes(doc, name))
                            else:
                                root.newChild(None, name, str(value))
                        else:
                            if is_cdata:
                                new_node = root.newChild(None, name, None)
                                new_node.addChild(doc.newCDataBlock(value, len(value)))
                            else:
                                root.newChild(None, name, value)
            except Exception, e:
                log_xml.exception("%s.%s value=%s", self.__class__.__name__, name, value)
                
        return root

    def init_from_xml_node(self, xml_node, scope='base', obj_name=None):
        elements, attributes = self.get_elements_and_attributes()

        if debug:
            #log_xml.debug("init_from_xml_node(): scope=%s obj_name='%s' xml_node=%s", scope, obj_name, repr(xml_node))
            pass

        doc = xml_node.get_doc()
        context = doc.xpathNewContext()
        context.setContextNode(xml_node)

        if debug:
            #log_xml.debug("doc=%s\n%s\nxml_node=%s\n%s", repr(doc), doc, repr(xml_node), xml_node)
            pass

        if scope == 'base':
            if xml_node.name == obj_name:
                root = xml_node
            else:
                context.xpathFreeContext()
                raise XMLNotFoundException(obj_name, self.__class__.__name__, scope, xml_node)
        elif scope == 'one':
            rootElements = context.xpathEval('./%s' % (obj_name))
            if len(rootElements) > 0:
                root = rootElements[0]
            else:
                context.xpathFreeContext()
                raise XMLNotFoundException(obj_name, self.__class__.__name__, scope, xml_node)
        elif scope == 'sub':
            rootElements = context.xpathEval('.//%s' % (obj_name))
            if len(rootElements) > 0:
                root = rootElements[0]
            else:
                context.xpathFreeContext()
                raise XMLNotFoundException(obj_name, self.__class__.__name__, scope, xml_node)
        else:
            context.xpathFreeContext()
            raise ValueError("unknown search scope = %s" % scope)

        context.setContextNode(root)
        for name in attributes:
            str_value = root.prop(name)
            if str_value is not None:
                name_info = self._xml_info[name]
                if name_info.has_key('class'):
                    class_info = name_info['class']
                    class_name = class_info['name']
                    is_xml = class_info.get('is_xml', True)
                    if is_xml:
                        context.xpathFreeContext()
                        raise ValueError("Illegal use of xml in attribute (%s)" % name)
                    else:
                        code = "%s(str_value)" % (class_name)
                        self.__dict__[name] = eval(code)
                else:
                    self.__dict__[name] = str_value
        for name in elements:
            name_info = self._xml_info[name]
            nameNode = context.xpathEval("%s" % (name))
            if not nameNode:
                continue
            # Does this node have substructure?
            if name_info.has_key('list'):
                list_info = name_info['list']
                item_name = list_info['name']
                self.__dict__[name] = []
                # Iterate over children, e.g. list elements
                list = context.xpathEval("%s/%s" % (name,item_name))
                if list_info.has_key('class'):
                    class_info = list_info['class']
                    class_name = class_info['name']
                    is_xml = class_info.get('is_xml', True)
                    if is_xml:
                        code = "for listNode in list:\n  self.%s.append(%s(listNode, obj_name='%s'))" % (name, class_name, item_name)
                    else:
                        code = "for listNode in list:\n  self.%s.append(%s(listNode.getContent()))" % (name, class_name)
                elif list_info.has_key('text'):
                    code = "for listNode in list:\n  self.%s.append(listNode.getContent())" % (name)
                else:
                    context.xpathFreeContext()
                    raise ValueError('unknown element type')
                exec(code)
            else:
                node = nameNode[0]
                if name_info.has_key('class'):
                    class_info = name_info['class']
                    class_name = class_info['name']
                    # FIXME: this same logic should be replicated above for lists
                    is_xml = class_info.get('is_xml', True)
                    if is_xml:
                        code = "%s(node, obj_name='%s')" % (class_name, name)
                    else:
                        str_value = node.getContent()
                        code = "%s(str_value)" % (class_name)
                    self.__dict__[name] = eval(code)
                else:
                    self.__dict__[name] = node.getContent()

        context.xpathFreeContext()

#------------------------------------------------------------------------

class AvcContext(XmlSerialize):
    def __init__(self, data=None, **kwds):
        if type(data) is StringType:
            fields = data.split(':')
            if len(fields) >= 3:
                data = {}
                data['user'] = fields[0]
                data['role'] = fields[1]
                data['type'] = fields[2]
                if len(fields) > 3:
                    data['mls'] = string.join(fields[3:], ':')
                else:
                    data['mls'] = 's0'
        super(AvcContext, self).__init__(AvcContextAttrs, data, **kwds)
        
    def __str__(self):
        return '%s:%s:%s:%s' % (self.user, self.role, self.type, self.mls)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        for name in self._xml_info.keys():
            if self.__dict__[name] != other.__dict__[name]:
                return False
        return True
        

class AVC(XmlSerialize):
    # These are the perm sets from the reference policy for file, dirs, and filesystems.
    # They are here to be used below in the access matching functions. The trailing
    # space is important - makes it simple to concatenate the strings.
    stat_file_perms =  "getattr "
    x_file_perms = "getattr execute "
    r_file_perms = "read getattr lock ioctl "
    rx_file_perms = "read getattr lock execute ioctl "
    ra_file_perms = "ioctl read getattr lock append "
    link_file_perms = "getattr link unlink rename "
    create_lnk_perms = "create read getattr setattr link unlink rename "
    create_file_perms = "create ioctl read getattr lock write setattr append link unlink rename "
    r_dir_perms = "read getattr lock search ioctl "
    rw_dir_perms = "read getattr lock search ioctl add_name remove_name write "
    ra_dir_perms = "read getattr lock search ioctl add_name write "
    create_dir_perms = "create read getattr lock setattr ioctl link unlink rename " \
                       + "search add_name remove_name reparent write rmdir "
    mount_fs_perms = " mount remount unmount getattr "
    search_dir_perms = "getattr search "
    getattr_dir_perms = "getattr "
    setattr_dir_perms = "setattr "
    list_dir_perms = "getattr search read lock ioctl "
    add_entry_dir_perms = "getattr search lock ioctl write add_name "
    del_entry_dir_perms = "getattr search lock ioctl write remove_name "
    manage_dir_perms = "create getattr setattr read write link unlink rename search add_name " \
                       + "remove_name reparent rmdir lock ioctl "
    getattr_file_perms = "getattr "
    setattr_file_perms = "setattr "
    read_file_perms = "getattr read lock ioctl "
    append_file_perms = "getattr append lock ioctl "
    write_file_perms = "getattr write append lock ioctl "
    rw_file_perms = "getattr read write append ioctl lock "
    delete_file_perms = "getattr unlink "
    manage_file_perms = "create getattr setattr read write append rename link unlink ioctl lock "


    def __init__(self, data=None, **kwds):
        super(AVC, self).__init__(AVCAttrs, data, **kwds)

        if self.scontext is not None and not isinstance(self.scontext, AvcContext):
            self.scontext = AvcContext(self.scontext)

        if self.tcontext is not None and not isinstance(self.tcontext, AvcContext):
            self.tcontext = AvcContext(self.tcontext)
        
    def __str__(self):
        return self.format_avc()

    # Nicer str conversion - with the possibility of ignoring fields
    def format_avc(self, ignore=None):
        ig = []
        if ignore is not None:
            ig.extend(ignore)
        ig.append("access")
        s = "avc: denied { %s } for " % " ".join([x for x in self.access])
        for name in self._names:
            if getattr(self, name) is None:
                continue
            if name in ig:
                continue
            s = s + "%s=%s " % (name, fmt_obj(getattr(self, name)))
        return s
                           
    # Below are helper functions to get values that might be
    # stored in one or more fields in an AVC.
    
    def get_binary(self):
        if self.exe is not None and self.exe.strip('"') not in INVALID_EXES:
            return audit_msg_decode(self.exe)
        if self.comm is not None:
            return audit_msg_decode(self.comm)
        return None

    def get_path(self):
        '''Examine the 'path' fields, look to see if the string begins with a
	  slash for a fully qualified path, if not it look to see if its a 
	  pseudo path such as 'pipe[12345]' or 'socket[12345]' and if so strip out
	  the instance information inside the brackets and return just the type of 
	  the pseudo path. This is done because we do not want path information
	  in the signature to be unique for each instance of the denial.'''
        
        if self.path is not None:
            path = audit_msg_decode(self.path)
            if path.startswith('/'): return path
            match = instance_path_re.search(path)
            if match:
                return match.group(1)
        return None

    def __accessStrToList(self, str):
        return str.strip().split(" ")

    def accessMatchAny(self, access_list):
        """
        Returns true if the AVC contains _any_ of the permissions
        in the access list. The access list is string with permissions
        separated by space.
        """
        targets = self.__accessStrToList(access_list)
        
        for a in self.access:
            if a in targets:
                return True
                
        return False

    def accessMatchOne(self, access_list):
        """
        Returns true if _every_ access in the AVC matches at
        least one of the permissions in the access list. The
        access list is string with permissions separated by
        space.
        """
        targets = self.__accessStrToList(access_list)

        for a in self.access:
            if a not in targets:
                return False
                
        return True

    def __typeMatch(self, context, type_list):
        types = type_list.strip().split(" ")

        for type in types:
            if re.match(type, context.type):
                return True
        return False

    def sourceTypeMatch(self, type_list):
        """
        Returns true if the type in the source context of the
        avc matches any of the types in the type list. The
        type list is a string with types separated by space.
        """
        return self.__typeMatch(self.scontext, type_list)

    def targetTypeMatch(self, type_list):
        """
        Returns true if the type in the target context of the
        avc matches any of the types in the type list. The
        type list is a string with types separated by space.
        """
        return self.__typeMatch(self.tcontext, type_list)


    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        for name in self._xml_info.keys():
            if self.__dict__[name] != other.__dict__[name]:
                return False
        return True

class SEFaultSignature(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEFaultSignature, self).__init__(SEFaultSignatureAttrs, data, **kwds)
        
class SEFaultSignatureInfo(XmlSerialize):
    merge_include = ['solution', 'category', 'environment', 'avc_list',
                     'src_rpm_list', 'tgt_rpm_list', 'object_path', 'last_seen_date']


    def __init__(self, data=None, **kwds):
        super(SEFaultSignatureInfo, self).__init__(SEFaultSignatureInfoAttrs, data, **kwds)
        
    def update_merge(self, siginfo):
        for name in self.merge_include:
            self.__dict__[name] = siginfo.__dict__[name]
        

    def get_user_data(self, username):
        for user in self.users:
            if user.username == username:
                return user
        if debug:
            log_sig.debug("new SEFaultSignatureUser for %s", username)
        user = SEFaultSignatureUser(username=username)
        self.users.append(user)
        return user

    def find_filter_by_username(self, username):
        if debug:
            log_sig.debug("find_filter_by_username %s", username)
        
        filter = None
        user_data = self.get_user_data(username)
        if user_data is not None:
            filter = user_data.filter
        return filter

    def update_user_filter(self, username, filter_type, data=None):
        user_data = self.get_user_data(username)
        user_data.update_filter(filter_type, data)

    def evaluate_filter_for_user(self, username, filter_type=None):
        action = 'display'
        f = self.find_filter_by_username(username)
        if debug:
            log_rpc.debug("evaluate_filter_for_user: found %s user's filter = %s", username, f)
        if f is not None:
            if filter_type is not None:
                f.filter_type = filter_type
            action = self.evaluate_filter(f)
            if debug:
                log_alert.debug("evaluate_filter_for_user: found filter for %s: %s\n%s",
                                username, action, f)
        return action
        
    def evaluate_filter(self, filter):
        filter_type = filter.filter_type
        
        action = 'display'

        if filter_type == FILTER_NEVER:
            action = 'display'
        elif filter_type == FILTER_AFTER_FIRST:
            if filter.count == 0:
                action = 'display'
            else:
                action = 'ignore'
        elif filter_type == FILTER_TILL_FIX:
            pass
        elif filter_type == FILTER_TILL_RPM_CHANGE or \
             filter_type == FILTER_TILL_POLICY_CHANGE:
            action = 'ignore'
            for rpmNVR in filter.rpm_watch_list:
                rpmName = split_rpm_nvr(rpmNVR)[0]
                if debug:
                    log_sig.debug("checking rpm %s name=%s", rpmNVR, rpmName)
                curRpmNVR = get_rpm_nvr_by_name(rpmName)
                if rpmNVR != curRpmNVR:
                    action = 'display'
                    break
        elif filter_type == FILTER_ALWAYS:
            action = 'ignore'
        elif filter_type == FILTER_TILL_DATE:
            if filter.till_date.in_future():
                action = 'ignore'
            else:
                action = 'display'
        else:
            raise ValueError("unknown filter_type (%s)" % (filter_type))
        filter.count += 1
        return action

    def format_unique_contexts(self, ctx_name):
        s = set()
        for avc in self.avc_list:
            (rc, trans) = selinux.selinux_raw_to_trans_context(str(getattr(avc, ctx_name)))
            s.add(trans)
        return ", ".join([str(x) for x in s])

    def format_unique_objs(self):
        s = set()
        [s.add((avc.get_path(), avc.tclass)) for avc in self.avc_list]
        return ", ".join(["%s [ %s ]" % x for x in s])

    def format_rpms(self):
        s = ""
        if len(self.src_rpm_list) > 0:
            s = " ".join(["%s [application]" % s for s in self.src_rpm_list if s])
        if len(self.tgt_rpm_list) > 0:
            return s + " ".join(["%s [target]" % s for s in self.tgt_rpm_list if s])
        else:
            return s

    def format_avcs(self):
        ignore = ["a0", "a1", "a2", "a3", "auid", "arch", "success", "syscall"]
        return [avc.format_avc(ignore) for avc in self.avc_list]

    def format_html(self, foreground_color="000000", background_color='#FFFFFF'):
        def default_text(obj):
            if obj is None:
                return '&nbsp;'
            return str(obj)

        def default_date_text(date):
            if date is None:
                return '&nbsp;'
            return date.format()

        env = self.environment
        summary = remove_linebreaks(self.solution.summary)
        description = remove_linebreaks(self.solution.problem_description)
        fix = remove_linebreaks(self.solution.fix_description)
        fixcmd = remove_linebreaks(self.solution.fix_cmd)
        if self.line_numbers is None:
            line_numbers = None
        else:
            line_numbers = ','.join([str(x) for x in self.line_numbers])


        tr1_fmt = '<tr bgcolor="%s"><td><font color="%s">%%s</font></td></tr>\n' % \
                  (foreground_color, background_color)
        tr2_fmt = '<tr><td><font color="%s">%%s</font></td></tr>\n' % \
                  (foreground_color)
        p_fmt = '<p>%s\n'

        avcs = ''
        for avc in self.format_avcs():
            avcs += p_fmt % avc
            
        if fixcmd:
            fix += '<br><br>%s<pre>%s</pre>' % (_("The following command will allow this access:"), fixcmd)

        html = ''

        # Wrap entire alert in one table
        html += '<table bgcolor=%s><tr><td>\n' % (background_color)

        # 1st table: primary Information

        html += '<table width="100%" cellspacing="1" cellpadding="1">\n'

        html += tr1_fmt % (_("Summary"))
        html += tr2_fmt % (summary)

        html += tr1_fmt % (_("Detailed Description"))
        html += tr2_fmt % (description)

        html += tr1_fmt % (_("Allowing Access"))
        html += tr2_fmt % (fix)

        html += tr1_fmt % (_("Additional Information"))
        html += tr2_fmt % ('')

        html += '</table>\n'

        # 2nd table: supplementary information


        tr1_fmt = '<tr><td><font color="%s">%%s:&nbsp;&nbsp;</td><td>%%s</font></td></tr>\n' % \
                  (foreground_color)
        html += '<table border="0" cellspacing="1" cellpadding="1">\n'

        html += tr1_fmt % (_("Source Context"),        self.format_unique_contexts('scontext'))
        html += tr1_fmt % (_("Target Context"),        self.format_unique_contexts('tcontext'))
        html += tr1_fmt % (_("Target Objects"),        self.format_unique_objs())
        html += tr1_fmt % (_("Affected RPM Packages"), default_text(self.format_rpms()))
        html += tr1_fmt % (_("Policy RPM"),            default_text(env.policy_rpm))
        html += tr1_fmt % (_("Selinux Enabled"),       default_text(env.selinux_enabled))
        html += tr1_fmt % (_("Policy Type"),           default_text(env.policy_type))
        html += tr1_fmt % (_("MLS Enabled"),           default_text(env.selinux_mls_enabled))
        html += tr1_fmt % (_("Enforcing Mode"),        default_text(env.enforce))
        html += tr1_fmt % (_("Plugin Name"),           default_text(self.sig.analysis_id))
        html += tr1_fmt % (_("Host Name"),             default_text(env.hostname))
        html += tr1_fmt % (_("Platform"),              default_text(env.uname))
        html += tr1_fmt % (_("Alert Count"),           default_text(self.report_count))
        html += tr1_fmt % (_("First Seen"),            default_date_text(self.first_seen_date))
        html += tr1_fmt % (_("Last Seen"),             default_date_text(self.last_seen_date))
        html += tr1_fmt % (_("Local ID"),              default_text(self.local_id))
        html += tr1_fmt % (_("Line Numbers"),          default_text(line_numbers))
        html += '</table>'

        html += p_fmt % _("Raw Audit Messages") + ':'
        html += avcs
            
        # close the entire encapsultating table
        html += '</td></tr></table>\n'

        return html

    def format_text(self):
        indent = 4

        def default_text(obj):
            if obj is None:
                return ''
            return str(obj)

        def default_date_text(date):
            if date is None:
                return ''
            return date.format()

        env = self.environment
        summary = remove_linebreaks(self.solution.summary)
        description = remove_html(self.solution.problem_description)
        fix = remove_html(self.solution.fix_description)
        fixcmd = remove_linebreaks(self.solution.fix_cmd)
        if self.line_numbers is None:
            line_numbers = None
        else:
            line_numbers = ','.join([str(x) for x in self.line_numbers])

        text = ''

        text += format_msg(_("Summary"), summary, indent)
        text += format_msg(_("Detailed Description"), description, indent)
        text += format_msg(_("Allowing Access"), fix, indent)
        if fixcmd:
            text += ' ' * indent + _("The following command will allow this access:") + '\n'
            text += ' ' * indent + fixcmd + '\n\n'


        text += format_2_column_name_value(_("Additional Information"), '\n')

        text += format_2_column_name_value(_("Source Context"),        self.format_unique_contexts('scontext'))
        text += format_2_column_name_value(_("Target Context"),        self.format_unique_contexts('tcontext'))
        text += format_2_column_name_value(_("Target Objects"),        self.format_unique_objs())
        text += format_2_column_name_value(_("Affected RPM Packages"), default_text(self.format_rpms()))
        text += format_2_column_name_value(_("Policy RPM"),            default_text(env.policy_rpm))
        text += format_2_column_name_value(_("Selinux Enabled"),       default_text(env.selinux_enabled))
        text += format_2_column_name_value(_("Policy Type"),           default_text(env.policy_type))
        text += format_2_column_name_value(_("MLS Enabled"),           default_text(env.selinux_mls_enabled))
        text += format_2_column_name_value(_("Enforcing Mode"),        default_text(env.enforce))
        text += format_2_column_name_value(_("Plugin Name"),           default_text(self.sig.analysis_id))
        text += format_2_column_name_value(_("Host Name"),             default_text(env.hostname))
        text += format_2_column_name_value(_("Platform"),              default_text(env.uname))
        text += format_2_column_name_value(_("Alert Count"),           default_text(self.report_count))
        text += format_2_column_name_value(_("First Seen"),            default_date_text(self.first_seen_date))
        text += format_2_column_name_value(_("Last Seen"),             default_date_text(self.last_seen_date))
        text += format_2_column_name_value(_("Local ID"),              default_text(self.local_id))
        text += format_2_column_name_value(_("Line Numbers"),          default_text(line_numbers))

        text += '\n'
        text += format_2_column_name_value(_("Raw Audit Messages"), '\n')
        for avc in self.format_avcs():
            text += wrap_text(avc)

        text += '\n'
        return text

class SEFilter(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEFilter, self).__init__(SEFilterAttrs, data, **kwds)
        

class SEFaultUserInfo(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEFaultUserInfo, self).__init__(SEFaultUserInfoAttrs, data, **kwds)

    def add_email_address(self, email_address):
        if not email_address in self.email_address_list:
            self.email_address_list.append(email_address)

class SEFaultUserSet(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEFaultUserSet, self).__init__(SEFaultUserSetAttrs, data, **kwds)

    def get_user(self, username):
        for user in self.user_list:
            if username == user.username:
                return user
        return None

    def add_user(self, username):
        if self.get_user(username) is not None:
            return
        user = SEFaultUserInfo(username=username)
        self.user_list.append(user)
        return user

class SEFaultSignatureUser(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEFaultSignatureUser, self).__init__(SEFaultSignatureUserAttrs, data, **kwds)
        
    def update_item(self, item, data):
        if not item in self._names:
            raise ProgramError(ERR_NOT_MEMBER, 'item (%s) is not a defined member' % item)

        if item == 'username':
            raise ProgramError(ERR_ILLEGAL_USER_CHANGE, 'changing the username is illegal')
            
        self.__dict__[item] = data

    def update_filter(self, filter_type, data=None):
        if debug:
            log_sig.debug("update_filter: filter_type=%s data=%s", filter_type, data)
        if filter_type == FILTER_NEVER or \
           filter_type == FILTER_AFTER_FIRST or \
           filter_type == FILTER_ALWAYS or \
           filter_type == FILTER_TILL_FIX:
            if debug:
                log_sig.debug("update_filter: !!!")
            self.filter = SEFilter(filter_type=filter_type)
            return True
        elif filter_type == FILTER_TILL_RPM_CHANGE or \
             filter_type == FILTER_TILL_POLICY_CHANGE:
            # FIXME: should rpm_watch_list be merged instead of overwrittten?
            self.filter = SEFilter(filter_type=filter_type)
            return True
        elif filter_type == FILTER_DAY or \
             filter_type == FILTER_WEEK:

            timestamp = TimeStamp()

            if filter_type == FILTER_DAY:
                timestamp.add(days=1)
            elif filter_type == FILTER_WEEK:
                timestamp.add(days=7)

            self.filter = SEFilter(filter_type=FILTER_TILL_DATE, till_date=timestamp)
            return True
        else:
            raise ValueError("Bad filter_type (%s)" % filter_type)

class SEFaultSignatureSet(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEFaultSignatureSet, self).__init__(SEFaultSignatureSetAttrs, data, **kwds)
        
    def siginfos(self):
        for siginfo in self.signature_list:
            yield siginfo

    def add_siginfo(self, siginfo):
        self.signature_list.append(siginfo)
        return siginfo

    def remove_siginfo(self, siginfo):
        self.signature_list.remove(siginfo)

    def clear(self):
        self.signature_list = []
        

    def generate_local_id(self):
        return str(uuid.uuid4())

    def lookup_local_id(self, local_id):
        if local_id is None:
            return None

        for siginfo in self.signature_list:
            if siginfo.local_id == local_id:
                return siginfo

        return None

    def match_signatures(self, pat, criteria='exact', xml_info=SEFaultSignatureAttrs):
        match_targets = xml_info.keys()
        exact = False
        if criteria == 'exact':
            exact = True
        elif type(criteria) is FloatType:
            num_match_targets = len(match_targets)
            score_per_match_target = 1.0 / num_match_targets
        else:
            raise ValueError("unknown criteria = %s" % criteria)
        
        matches = []
        for siginfo in self.signature_list:
            score = 0.0
            sig = siginfo.sig
            for name in match_targets:
                if pat.__dict__[name] == sig.__dict__[name]:
                    if exact:
                        score = 1.0
                    else:
                        score += score_per_match_target
                else:
                    if exact:
                        score = 0.0
                        break
            if exact:
                if score == 1.0:
                    matches.append(SignatureMatch(siginfo, score))
            else:
                if score >= criteria:
                    matches.append(SignatureMatch(siginfo, score))
        matches.sort((lambda a,b: cmp(b.score, a.score)))
        return matches

class SEFaultSolution(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEFaultSolution, self).__init__(SEFaultSolutionAttrs, data, **kwds)
        
class SEEnvironment(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEEnvironment, self).__init__(SEEnvironmentAttrs, data, **kwds)

    def update(self):
        import platform
        # security_getenforce is the same as the getenforce command.
        # selinux_getenforcemode tells you what is set in /etc/selinux/config

        self.platform, self.kernel = get_os_environment()
        self.policy_type = selinux.selinux_getpolicytype()[1]
        self.policy_rpm = get_rpm_nvr_by_name("selinux-policy")
        self.policyvers = str(selinux.security_policyvers())
        enforce = selinux.security_getenforce()
        if enforce == 0:
            self.enforce = "Permissive"
        else:
            self.enforce = "Enforcing"

        self.selinux_enabled = bool(selinux.is_selinux_enabled())
        self.selinux_mls_enabled = bool(selinux.is_selinux_mls_enabled())
        self.hostname = platform.node()
        self.uname = " ".join(platform.uname())

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        for name in self._xml_info.keys():
            if self.__dict__[name] != other.__dict__[name]:
                return False
        return True


class SEDatabaseProperties(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEDatabaseProperties, self).__init__(SEDatabasePropertiesAttrs, data, **kwds)


class SEEmailRecipient(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEEmailRecipient, self).__init__(SEEmailRecipientAttrs, data, **kwds)

    def __str__(self):
        return "%s:%s" % (self.address, map_filter_value_to_name.get(self.filter_type, 'unknown'))

class SEEmailRecipientSet(XmlSerialize):
    def __init__(self, data=None, **kwds):
        super(SEEmailRecipientSet, self).__init__(SEEmailRecipientSetAttrs, data, **kwds)

    def __str__(self):
        return ','.join([str(x) for x in self.recipient_list])

    def find_address(self, address):
        address = address.strip()
        for recipient in self.recipient_list:
            if address == recipient.address:
                return recipient
        return None

    def add_address(self, address, filter_type=FILTER_AFTER_FIRST):
        address = address.strip()
        if not valid_email_address(address):
            raise ProgramError(ERR_INVALID_EMAIL_ADDR, detail="address='%s'" % address)
            return

        recipient = self.find_address(address)
        if recipient is not None:
            return
        self.recipient_list.append(SEEmailRecipient(address=address, filter_type=filter_type))

    def clear_recipient_list(self):
        self.recipient_list = []

    def parse_recipient_file(self, filepath):
        comment_re = re.compile('#.*')
        entry_re = re.compile('(\S+)(\s+(.+))?')
        key_value_re = re.compile("(\w+)\s*=\s*(\S+)")

        map_boolean = {'enabled'  : True,
                       'true'     : True,
                       'yes'      : True,
                       'on'       : True,
                       'disabled' : False,
                       'false'    : False,
                       'no'       : False,
                       'off'      : False,
                       }


        try:
            f = open(filepath)
        except IOError, e:
            raise ProgramError(ERR_FILE_OPEN, detail="%s, %s" % (filepath, e.strerror))

        self.clear_recipient_list()

        for line in f.readlines():
            line = comment_re.sub('', line)
            line = line.strip()
            if line:
                match = entry_re.search(line)
                if match:
                    address = match.group(1)
                    options = match.group(3)
                    filter_type = None

                    if options:
                        for match in key_value_re.finditer(options):
                            option = match.group(1)
                            value  = match.group(2)


                            if option == 'filter_type':
                                filter_type = map_filter_name_to_value.get(value.lower(), None)
                                if filter_type is None:
                                    log_email.warn("unknown email filter (%s) for address %s", option, address)
                                    
                            else:
                                log_email.warn("unknown email option (%s) for address %s", option, address)
                                
                    try:
                        self.add_address(address, filter_type)
                    except ProgramError, e:
                        if e.errno == ERR_INVALID_EMAIL_ADDR:
                            log_email.warn(e.strerror)
                        else:
                            raise e


        f.close()

    def write_recipient_file(self, filepath):
        try:
            f = open(filepath, 'w')
        except IOError, e:
            raise ProgramError(ERR_FILE_OPEN, detail="%s, %s" % (filepath, e.strerror))

        for recipient in self.recipient_list:
            filter_type = map_filter_value_to_name[recipient.filter_type]
            f.write("%-40s filter_type=%s\n" % (recipient.address, filter_type))
        
        f.close()

# --- Main ---

if __name__ == "__main__":
    sigs = SEFaultSignatureSet()
    sigs.read_xml_file('/var/lib/setroubleshoot/database.xml', 'sigs')
    siginfo = sigs.signature_list[0]
    from setroubleshoot.email_alert import *
    email_alert(siginfo, ['jdennis@redhat.com'])

    text = siginfo.format_text()
    html = siginfo.format_html()
    print text
    print html
    f = open('siginfo.html', 'w')
    f.write(html)
    f.close()


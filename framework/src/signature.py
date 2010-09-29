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

from subprocess import *

__all__ = [
           'SignatureMatch',
           'SEFilter',
           'SEFaultSignature',
           'SEFaultSignatureInfo',
           'SEFaultSignatureSet',
           'SEFaultSignatureUser',
           'SEEnvironment',
           'SEDatabaseProperties',
           'SEFaultUserInfo',
           'SEFaultUserSet',
           'SEPlugin',
           'SEEmailRecipient',
           'SEEmailRecipientSet',

           'FILTER_NEVER',
           'FILTER_ALWAYS',
           'FILTER_AFTER_FIRST',
           'filter_text'
           ]

if __name__ == "__main__":
    import gettext
    from setroubleshoot.config import parse_config_setting, get_config
    gettext.install(domain    = get_config('general', 'i18n_text_domain'),
		    localedir = get_config('general', 'i18n_locale_dir'))
    from setroubleshoot.log import log_init
    log_init('test', {'console':True,
			   'level':'debug'})

from gettext import ngettext as P_
from setroubleshoot.config import get_config
from setroubleshoot.errcode import *
from setroubleshoot.util import *
from setroubleshoot.xml_serialize import *
from setroubleshoot.log import *
from setroubleshoot.util import *
from setroubleshoot.html_util import *
import setroubleshoot.uuid as uuid
from setroubleshoot.audit_data import *
import hashlib
from types import *
from string import Template
import re, os

# Don't reuse the numeric values!
FILTER_NEVER              = 0
FILTER_ALWAYS             = 4
FILTER_AFTER_FIRST        = 8

filter_text = {
    FILTER_NEVER              : _("Never Ignore"),
    FILTER_ALWAYS             : _("Ignore Always"),
    FILTER_AFTER_FIRST        : _("Ignore After First Alert"),
    }

map_filter_value_to_name = {
    FILTER_NEVER              : 'never',
    FILTER_ALWAYS             : 'always',
    FILTER_AFTER_FIRST        : 'after_first',
    }

map_filter_name_to_value = {
    'never'                   : FILTER_NEVER,
    'always'                  : FILTER_ALWAYS,
    'after_first'             : FILTER_AFTER_FIRST,
    }

#------------------------------------------------------------------------

class SignatureMatch(object):
    def __init__(self, siginfo, score):
        self.siginfo = siginfo
        self.score = score


class SEEnvironment(XmlSerialize):
    _xml_info = {
    'version'             : {'XMLForm':'attribute','default':lambda: '1.0' },
    'platform'            : {'XMLForm':'element' },
    'kernel'              : {'XMLForm':'element' },
    'policy_type'         : {'XMLForm':'element' },
    'policy_rpm'          : {'XMLForm':'element' },
    'enforce'             : {'XMLForm':'element' },
    'selinux_enabled'     : {'XMLForm':'element', 'import_typecast':boolean, },
    'selinux_mls_enabled' : {'XMLForm':'element', 'import_typecast':boolean, },
    'policyvers'          : {'XMLForm':'element' },
    'hostname'            : {'XMLForm':'element' },
    'uname'               : {'XMLForm':'element' },
    }

    def __init__(self):
        super(SEEnvironment, self).__init__()
        self.update()

    def update(self):
        import platform
        import selinux
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
            if getattr(self, name) != getattr(other, name):
                return False
        return True



class SEFilter(XmlSerialize):
    _xml_info = {
    'filter_type'      : {'XMLForm':'element', 'import_typecast':int, 'default':lambda: FILTER_NEVER },
    'count'            : {'XMLForm':'element', 'import_typecast':int, 'default':lambda: 0 },
    }
    def __init__(self, filter_type=FILTER_NEVER):
        super(SEFilter, self).__init__()
        self.filter_type = filter_type
        

class SEFaultSignatureUser(XmlSerialize):
    _xml_info = {
    'username'         : {'XMLForm':'attribute' },
    'seen_flag'        : {'XMLForm':'attribute', 'import_typecast':boolean, 'default': lambda: False },
    'delete_flag'      : {'XMLForm':'attribute', 'import_typecast':boolean, 'default': lambda: False },
    'filter'           : {'XMLForm':'element', 'import_typecast':SEFilter, 'default': lambda: SEFilter() },
    }
    def __init__(self, username):
        super(SEFaultSignatureUser, self).__init__()
        self.username = username
        
    def update_item(self, item, data):
        if not item in self._names:
            raise ProgramError(ERR_NOT_MEMBER, 'item (%s) is not a defined member' % item)

        if item == 'username':
            raise ProgramError(ERR_ILLEGAL_USER_CHANGE, 'changing the username is illegal')
            
        setattr(self, item, data)

    def update_filter(self, filter_type, data=None):
        if debug:
            log_sig.debug("update_filter: filter_type=%s data=%s", map_filter_value_to_name.get(filter_type, 'unknown'), data)
        if filter_type == FILTER_NEVER or \
           filter_type == FILTER_AFTER_FIRST or \
           filter_type == FILTER_ALWAYS:
            if debug:
                log_sig.debug("update_filter: !!!")
            self.filter = SEFilter(filter_type=filter_type)
            return True
        else:
            raise ValueError("Bad filter_type (%s)" % filter_type)


class_dict = {}
class_dict['dir']     = _("directory")
class_dict['sem']     = _("semaphore")
class_dict['shm']     = _("shared memory")
class_dict['msgq']    = _("message queue")
class_dict['msg']     = _("message")
class_dict['file']    = _("file")
class_dict['socket']  = _("socket")
class_dict['process'] = _("process")
class_dict['filesystem'] = _("filesystem")
class_dict['node'] = _("node")
class_dict['capability'] = _("capability")

def translate_class(tclass):
    if tclass in class_dict.keys():
        return class_dict[tclass]
    return tclass

# --

class AttributeValueDictionary(XmlSerialize):
    _xml_info = 'unstructured'
    def __init__(self):
        super(AttributeValueDictionary, self).__init__()

class SEFaultSignature(XmlSerialize):
    _xml_info = {
    'version'          : {'XMLForm':'attribute','default':lambda: '4.0', },
    'host'             : {'XMLForm':'element', },
    'access'           : {'XMLForm':'element', 'list':'operation', },
    'scontext'         : {'XMLForm':'element', 'import_typecast':AvcContext },
    'tcontext'         : {'XMLForm':'element', 'import_typecast':AvcContext },
    'tclass'           : {'XMLForm':'element', },
    'port'             : {'XMLForm':'element', 'import_typecast':int, },
    }
    def __init__(self, **kwds):
        super(SEFaultSignature, self).__init__()
        for k,v in kwds.items():
            setattr(self, k, v)
        
class SEPlugin(XmlSerialize):
    _xml_info = {
    'analysis_id'          : {'XMLForm':'element'},
    'args'                 : {'XMLForm':'element', 'list':'arg', },
    }

    def __init__(self, analysis_id, args):
        super(SEPlugin, self).__init__()
        self.analysis_id = analysis_id;
        self.args = args;

    def __str__(self):
        return str((self.analysis_id, self.args))

class SEFaultSignatureInfo(XmlSerialize):
    _xml_info = {
        'plugin_list'       : {'XMLForm':'element', 'list':'plugin', 'import_typecast':SEPlugin },
        'audit_event'      : {'XMLForm':'element', 'import_typecast':AuditEvent },
        'source'           : {'XMLForm':'element' },
        'spath'            : {'XMLForm':'element' },
        'tpath'            : {'XMLForm':'element' },
        'src_rpm_list'     : {'XMLForm':'element', 'list':'rpm', },
        'tgt_rpm_list'     : {'XMLForm':'element', 'list':'rpm', },
        'scontext'         : {'XMLForm':'element', 'import_typecast':AvcContext },
        'tcontext'         : {'XMLForm':'element', 'import_typecast':AvcContext },
        'tclass'           : {'XMLForm':'element', },
        'port'             : {'XMLForm':'element', 'import_typecast':int, },

        'sig'              : {'XMLForm':'element', 'import_typecast':SEFaultSignature },
        'if_text'          : {'XMLForm':'element' },
        'then_text'        : {'XMLForm':'element' },
        'do_text'          : {'XMLForm':'element' },
        'environment'      : {'XMLForm':'element',  'import_typecast':SEEnvironment },

        'first_seen_date'  : {'XMLForm':'element', 'import_typecast':TimeStamp },
        'last_seen_date'   : {'XMLForm':'element', 'import_typecast':TimeStamp },
        'report_count'     : {'XMLForm':'element', 'import_typecast':int, 'default':lambda: 0 },
        'local_id'         : {'XMLForm':'element' },
        'users'            : {'XMLForm':'element', 'list':'user', 'import_typecast':SEFaultSignatureUser, },
        'level'         : {'XMLForm':'element' },
        'fixable'       : {'XMLForm':'element' },
        'button_text'   : {'XMLForm':'element' },
        }

    merge_include = ['audit_event', 'tpath', 'src_rpm_list', 'tgt_rpm_list',
                     'scontext', 'tcontext', 'tclass', 'port',
                     'environment',
                     'last_seen_date'
                     ]


    def __init__(self, **kwds):
        super(SEFaultSignatureInfo, self).__init__()
        for k,v in kwds.items():
            setattr(self, k, v)
        self.report_count = 1
        self.plugin_list = []

    def update_merge(self, siginfo):
        for name in self.merge_include:
            setattr(self, name, getattr(siginfo, name))

        last_seen_date = TimeStamp(siginfo.last_seen_date)
        if last_seen_date != self.last_seen_date:
            self.last_seen_date = last_seen_date
            self.report_count += 1

    def get_hash_str(self):
        return  "%s,%s,%s,%s,%s" % (self.source, self.scontext.type, self.tcontext.type, self.tclass, ",".join(self.sig.access))

    def get_hash(self):
        hash = hashlib.sha256(self.get_hash_str())
        return hash.hexdigest()
        
    def get_user_data(self, username):
        for user in self.users:
            if user.username == username:
                return user
        if debug:
            log_sig.debug("new SEFaultSignatureUser for %s", username)
        user = SEFaultSignatureUser(username)
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
        elif filter_type == FILTER_ALWAYS:
            action = 'ignore'
        else:
            raise ValueError("unknown filter_type (%s)" % (filter_type))
        filter.count += 1
        return action

    def format_rpm_list(self, rpm_list):
        if isinstance(rpm_list, list):
            if  len(rpm_list) > 0:
                return " ".join(rpm_list)
            else:
                return ""
        else:
            return default_text(None)

    def format_target_object(self):
        return "%s [ %s ]" % (self.tpath, self.tclass)

    def description_adjusted_for_permissive(self):
        permissive_msg = None
        syscall_record = self.audit_event.get_record_of_type('SYSCALL')
        if syscall_record != None and syscall_record.get_field('success') == 'yes':
            permissive_msg = _("%s has a permissive type (%s). This access was not denied.") % (self.source, self.scontext.type)

        if self.environment.enforce == "Permissive":
            permissive_msg = _("SEinux is in permissive mode. This access was not denied.")

    def update_derived_template_substitutions(self):
        self.template_substitutions = {} 
        self.template_substitutions["SOURCE_TYPE"] = self.scontext.type
        self.template_substitutions["TARGET_TYPE"] = self.tcontext.type
        self.template_substitutions["SOURCE"]      = self.source
        self.template_substitutions["SOURCE_PATH"] = self.spath
        self.template_substitutions["SOURCE_BASE_PATH"] = os.path.basename(self.spath)
        if self.spath:
            self.template_substitutions["FIX_SOURCE_PATH"] = re.sub(" ",".",self.spath)
        self.template_substitutions["TARGET_PATH"] = self.tpath
        self.template_substitutions["TARGET_BASE_PATH"] = os.path.basename(self.tpath)
        if self.tpath:
            self.template_substitutions["FIX_TARGET_PATH"] = re.sub(" ",".",self.tpath)

        if self.tpath is None:
            self.template_substitutions["TARGET_DIR"] = None
        else:
            if self.tclass == 'dir':
                self.template_substitutions["TARGET_DIR"] = self.tpath
            elif self.tclass == 'file':
                self.template_substitutions["TARGET_DIR"] = os.path.dirname(self.tpath)
            else:
                self.template_substitutions["TARGET_DIR"] = None

        if self.tclass == "dir":
            self.template_substitutions["TARGET_CLASS"] = "directory"
        else:
            self.template_substitutions["TARGET_CLASS"] = self.tclass

        if self.sig.access is None:
            self.template_substitutions["ACCESS"] = None
        else:
            self.template_substitutions["ACCESS"] = ' '.join(self.sig.access)

        if len(self.src_rpm_list) > 0:
            self.template_substitutions["SOURCE_PACKAGE"] = self.src_rpm_list[0]
        self.template_substitutions["PORT_NUMBER"] = self.port

        # validate, replace any None values with friendly string
        for key, value in self.template_substitutions.items():
            if value is None:
                self.template_substitutions[key] = default_text(value)

    def priority_sort(self, x, y):
        return cmp(y[0].priority,x[0].priority)

    def summary(self):
        return P_("SELinux is preventing %s from %s access on the %s %s.", "SELinux is preventing %s from '%s' accesses on the %s %s.", len(self.sig.access)) % (self.spath, ", ".join(self.sig.access), translate_class(self.tclass), self.tpath)

    def get_plugins(self, all = False):
        self.plugins = load_plugins()
        plugins = []
        total_priority = 0
        if all:
            for p  in self.plugins:
                total_priority += p.priority
                plugins.append((p, ("allow_ypbind", "1")))
        else:
            for solution in self.plugin_list:
                for p  in self.plugins:
                    if solution.analysis_id == p.analysis_id:
                        total_priority += p.priority
                        plugins.append((p, tuple(solution.args)))
                        break

        plugins.sort(self.priority_sort)

        return total_priority, plugins

    def substitute(self, txt):
        return Template(txt).safe_substitute(self.template_substitutions)

    def format_text(self, all = False):
        env = self.environment
        self.update_derived_template_substitutions()

        text = self.summary() + "\n"

        total_priority, plugins = self.get_plugins(all)

        for p, args in plugins:
            text += _("\nPlugin %s (%d%% confidence) suggests: \n") % (p.analysis_id, ((float(p.priority) / float(total_priority)) * 100 + .5))
            txt = self.substitute(p.get_if_text(self.audit_event.records, args))
            text +=  _("\nIf ") + txt[0].lower() + txt[1:]
            txt = self.substitute(p.get_then_text(self.audit_event.records, args))
            text +=  _("\nThen ") + txt[0].lower() + txt[1:]

            txt = self.substitute(p.get_do_text(self.audit_event.records, args))
            text +=  _("\nDo\n") + txt[0].lower() + txt[1:]

        text += '\n\n' + _("Additional Information") + ':\n'

        text += format_2_column_name_value(_("Source Context"),        self.scontext.format())
        text += format_2_column_name_value(_("Target Context"),        self.tcontext.format())
        text += format_2_column_name_value(_("Target Objects"),        self.format_target_object())
        text += format_2_column_name_value(_("Source"),                default_text(self.source))
        text += format_2_column_name_value(_("Source Path"),           default_text(self.spath))
        text += format_2_column_name_value(_("Port"),                  default_text(self.port))
        text += format_2_column_name_value(_("Host"),                  default_text(self.sig.host))
        text += format_2_column_name_value(_("Source RPM Packages"),   default_text(self.format_rpm_list(self.src_rpm_list)))
        text += format_2_column_name_value(_("Target RPM Packages"),   default_text(self.format_rpm_list(self.tgt_rpm_list)))
        text += format_2_column_name_value(_("Policy RPM"),            default_text(env.policy_rpm))
        text += format_2_column_name_value(_("Selinux Enabled"),       default_text(env.selinux_enabled))
        text += format_2_column_name_value(_("Policy Type"),           default_text(env.policy_type))
        text += format_2_column_name_value(_("Enforcing Mode"),        default_text(env.enforce))
        text += format_2_column_name_value(_("Host Name"),             default_text(env.hostname))
        text += format_2_column_name_value(_("Platform"),              default_text(env.uname))
        text += format_2_column_name_value(_("Alert Count"),           default_text(self.report_count))
        text += format_2_column_name_value(_("First Seen"),            default_date_text(self.first_seen_date))
        text += format_2_column_name_value(_("Last Seen"),             default_date_text(self.last_seen_date))
        text += format_2_column_name_value(_("Local ID"),              default_text(self.local_id))

        text += '\n' + _("Raw Audit Messages")
        avcbuf = ""
        for audit_record in self.audit_event.records:
            if audit_record.record_type == 'AVC':
                avcbuf += "\n" + audit_record.to_text() + "\n"
            else:
                avcbuf += "\ntype=%s msg=%s: " % (audit_record.record_type, audit_record.event_id)
                avcbuf += ' '.join(["%s=%s" % (k, audit_record.fields[k]) for k in audit_record.fields_ord]) +"\n"

            avcbuf += self.get_hash_str() 

        try:
            p =  Popen(["audit2allow"], shell=True,stdin=PIPE, stdout=PIPE)
            avcbuf += p.communicate(avcbuf)[0]
        except:
            pass

        text += avcbuf + '\n'

        return text

class SEFaultUserInfo(XmlSerialize):
    _xml_info = {
    'version'            : {'XMLForm':'attribute','default':lambda: '1.0' },
    'username'           : {'XMLForm':'attribute' },
    'email_alert'        : {'XMLForm':'element', 'import_typecast':boolean, 'default': lambda: False },
    'email_address_list' : {'XMLForm':'element', 'list':'email_address', },
    }
    def __init__(self, username):
        super(SEFaultUserInfo, self).__init__()
        self.username = username

    def add_email_address(self, email_address):
        if not email_address in self.email_address_list:
            self.email_address_list.append(email_address)



class SEFaultUserSet(XmlSerialize):
    _xml_info = {
    'version'      : {'XMLForm':'attribute','default':lambda: '1.0' },
    'user_list'    : {'XMLForm':'element', 'list':'user', 'import_typecast':SEFaultUserInfo, },
    }
    def __init__(self):
        super(SEFaultUserSet, self).__init__()

    def get_user(self, username):
        for user in self.user_list:
            if username == user.username:
                return user
        return None

    def add_user(self, username):
        if self.get_user(username) is not None:
            return
        user = SEFaultUserInfo(username)
        self.user_list.append(user)
        return user



class SEFaultSignatureSet(XmlSerialize):
    _xml_info = {
    'version'          : {'XMLForm':'attribute','default':lambda: '%d.%d' %  (DATABASE_MAJOR_VERSION, DATABASE_MINOR_VERSION)},
    'users'            : {'XMLForm':'element', 'import_typecast':SEFaultUserSet, 'default': lambda: SEFaultUserSet() },
    'signature_list'   : {'XMLForm':'element', 'list':'siginfo', 'import_typecast':SEFaultSignatureInfo, },
    }
    def __init__(self):
        super(SEFaultSignatureSet, self).__init__()

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

    def match_signatures(self, pat, criteria='exact', xml_info=SEFaultSignature._xml_info):
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
                if getattr(pat, name) == getattr(sig, name):
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




class SEDatabaseProperties(XmlSerialize):
    _xml_info = {
    'name'          : {'XMLForm':'element' },
    'friendly_name' : {'XMLForm':'element' },
    'filepath'      : {'XMLForm':'element' },
    }
    def __init__(self, name=None, friendly_name=None, filepath=None):
        super(SEDatabaseProperties, self).__init__()
        if name is not None:
            self.name = name
        if friendly_name is not None:
            self.friendly_name = friendly_name
        if filepath is not None:
            self.filepath = filepath

class SEEmailRecipient(XmlSerialize):
    _xml_info = {
    'address'          : {'XMLForm':'element' },
    'filter_type'      : {'XMLForm':'element', 'import_typecast':int, 'default':lambda: FILTER_AFTER_FIRST },
    }
    def __init__(self, address, filter_type=None):
        super(SEEmailRecipient, self).__init__()
        self.address = address
        if filter_type is not None:
            self.filter_type = filter_type

    def __str__(self):
        return "%s:%s" % (self.address, map_filter_value_to_name.get(self.filter_type, 'unknown'))


class SEEmailRecipientSet(XmlSerialize):
    _xml_info = {
    'version'         : {'XMLForm':'attribute','default':lambda: '1' },
    'recipient_list'  : {'XMLForm':'element', 'list':'recipient', 'import_typecast':SEEmailRecipient, },
    }
    def __init__(self, recipient_list=None):
        super(SEEmailRecipientSet, self).__init__()
        if recipient_list is not None:
            self.recipient_list = recipient_list

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
        self.recipient_list.append(SEEmailRecipient(address, filter_type))

    def clear_recipient_list(self):
        self.recipient_list = []

    def parse_recipient_file(self, filepath):
        import re
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


#------------------------------------------------------------------------


if __name__ == '__main__':
    import libxml2
    #memory debug specific
    libxml2.debugMemory(1)

    xml_file = 'audit_listener_database.xml'

    sigs = SEFaultSignatureSet()
    sigs.read_xml_file(xml_file, 'sigs')
    siginfo = sigs.signature_list[0]
    record = siginfo.audit_event.records[0]
    print record.record_type
    print "siginfo.audit_event=%s" % siginfo.audit_event
    print sigs

    #memory debug specific
    libxml2.cleanupParser()
    if libxml2.debugMemory(1) == 0:
        print "Memory OK"
    else:
        print "Memory leak %d bytes" % (libxml2.debugMemory(1))
        libxml2.dumpMemory()

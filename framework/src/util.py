# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2006,2007,2008 Red Hat, Inc.
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

__all__ = [
    'audit_msg_decode',
    'merge_lists',
    'preextend_list',
    'fmt_obj',
    'format_elapsed_time',
    'format_2_column_name_value',
    'wrap_text',
    'format_msg',
    'remove_linebreaks',
    'default_text',
    'default_date_text',
    'get_standard_directories',
    'get_rpm_nvr_from_header',
    'get_rpm_nvr_by_name',
    'get_rpm_nvr_by_file_path',
    'is_hex',
    'split_rpm_nvr',
    'get_user_home_dir',
    'get_plugin_names',
    'load_plugins',
    'get_os_environment',
    'find_program',
    'get_identity',
    'get_hostname',
    'make_database_filepath',
    'valid_email_address',
    'launch_web_browser_on_url',
    'abstract',
    'get_error_from_socket_exception',
    'assure_file_ownership_permissions',
    'parse_datetime_offset',
    'DATABASE_MAJOR_VERSION',
    'DATABASE_MINOR_VERSION',
    'database_version_compatible',

    'TimeStamp',
    'Retry',
    ]

import datetime
import glob
import gobject
import os
import pwd
import re
import sys
import textwrap
import time
from types import *

from setroubleshoot.config import get_config
from setroubleshoot.errcode import *
from setroubleshoot.log import *


DATABASE_MAJOR_VERSION = 3
DATABASE_MINOR_VERSION = 0

redhat_release_path='/etc/redhat-release'
text_wrapper = textwrap.TextWrapper()
fix_newline_re = re.compile("\s*\n+\s*")
hex_re = re.compile('^[A-Fa-f0-9]+$')
href_re = re.compile('<a\s*href="([^"]+)"[^<]*</a>')
name_at_domain_re = re.compile('^([^\s@]+)@([^\s@]+)$')
audit_decode_re = re.compile(r'^\s*"([^"]+)"\s*$')

def database_version_compatible(version):
    major = minor = None
    components = version.split('.')
    if len(components) >= 1: major = int(components[0])
    if len(components) >= 2: minor = int(components[1])

    if major < DATABASE_MAJOR_VERSION:
        log_database.info("database version %s not compatible with current %d.%d version", 
                          version, DATABASE_MAJOR_VERSION, DATABASE_MINOR_VERSION)
        return False
    else:
        if debug:
            log_database.debug("database version %s compatible with current %d.%d version", 
                               version, DATABASE_MAJOR_VERSION, DATABASE_MINOR_VERSION)
        return True


def format_elapsed_time(elapsed_time):
    if elapsed_time is None:
        return None

    import math
    fraction, whole = math.modf(elapsed_time)
    whole = int(whole)

    days = whole/86400
    whole = whole - days*86400

    hours = whole/3600
    whole = whole - hours*3600
    
    minutes = whole/60
    seconds = whole - minutes*60
    
    if days:
        return "%dd:%dh:%dm:%.3fs" % (days,hours,minutes,seconds+fraction)
    if hours:
        return "%dh:%dm:%.3fs" % (hours,minutes,seconds+fraction)
    if minutes:
        return "%dm:%.3fs" % (minutes,seconds+fraction)
    return "%.3fs" % (seconds+fraction)

def is_hex(str):
    if hex_re.match(str):
        return True
    else:
        return False

def audit_msg_decode(msg):
    if msg is None:
        return None
    match = audit_decode_re.search(msg)
    if match:
        decoded = match.group(1)
    else:
        try:
            decoded = msg.decode('hex')
        except:
            decoded = msg
    return decoded

def merge_lists(a,b):
    'return a list containing the unique members of a+b'
    if not b: return a
    if not a: return b
    d = {}
    for i in a: d[i] = None
    for i in b: d[i] = None
    m = d.keys()
    return m

def preextend_list(requested_length, _list=None, default=None):
    if _list is None:
        _list = []
    cur_length = len(_list)
    delta = requested_length-cur_length
    if delta > 0:
        if type(default) is TypeType:
            _list.extend([default() for x in range(delta)])
        else:
            _list.extend([default] * delta)
    return _list

def fmt_obj(obj):
    if type(obj) is StringType:
        return obj
    elif type(obj) is ListType or type(obj) is TupleType:
        return "["+" ".join(["%s" % fmt_obj(x) for x in obj])+"]"
    elif type(obj) is DictType:
        keys = obj.keys()
        keys.sort()
        return "{"+" ".join(["%s=%s" % (fmt_obj(key), fmt_obj(obj[key])) for key in keys])+"}"
    else:
        return str(obj)

def format_2_column_name_value(name, value, value_indent=30, page_width=80):
    if len(name) >= value_indent:
        initial_indent = name[0:value_indent-1] + ' '
    else:
        initial_indent = name + ' ' * (value_indent - len(name))
        

    if not value or value.isspace():
        return initial_indent + value + '\n'
    else:
        text_wrapper.initial_indent    = initial_indent
        text_wrapper.subsequent_indent = ' ' * value_indent
        text_wrapper.width = page_width
        return text_wrapper.fill(value) + '\n'

def wrap_text(s, width=80, indent=0):
    prefix = ' ' * indent
    text_wrapper.initial_indent    = prefix
    text_wrapper.subsequent_indent = prefix
    text_wrapper.width = width
    return text_wrapper.fill(s) + '\n'

def format_msg(title, msg, indent=4):
    if msg is None:
        msg = ''
    msg = msg.strip()
    indentString = " " * indent
    text_wrapper.initial_indent    = indentString
    text_wrapper.subsequent_indent = indentString
    text_wrapper.width = 80
    return title + "\n" + text_wrapper.fill(msg) + "\n\n"

def remove_linebreaks(str):
    new_str = fix_newline_re.sub(" ", str).strip()
    if new_str is None:
        return ""
    else:
        return new_str

def default_text(val):
    if val is None:
        val = '<'+_('Unknown')+'>'
    return str(val)

def default_date_text(date):
    if date is None:
        return default_text(date)
    return date.format()

def get_standard_directories():
    lst = []
    import rpm
    try:
        ts = rpm.ts()
        h = ts.dbMatch("name", "filesystem").next()
        for i in h.fiFromHeader():
            lst.append(i[0])
    except:
        log_program.exception("failed to get filesystem list from rpm")
        
    return lst

def get_rpm_nvr_from_header(hdr):
    'Given an RPM header return the package NVR as a string'
    name    = hdr['name']
    version = hdr['version']
    release = hdr['release']

    return "%s-%s-%s" % (name, version, release)

def get_rpm_nvr_by_name(name):
    if name is None:
        return None

    import rpm
    nvr = None
    try:
        ts = rpm.ts()
        mi = ts.dbMatch(rpm.RPMTAG_NAME, name)
        for h in mi:
            nvr = get_rpm_nvr_from_header(h)
            break
    except:
        log_plugin.exception("failed to retrieve rpm info for %s", name)
    return nvr

def get_rpm_nvr_by_file_path(path):
    if path is None:
        return None

    import rpm
    nvr = None
    try:
        ts = rpm.ts()
        mi = ts.dbMatch(rpm.RPMTAG_BASENAMES, path)
        for h in mi:
            nvr = get_rpm_nvr_from_header(h)
            break
    except:
        log_plugin.exception("failed to retrieve rpm info for %s", path)
    return nvr

def split_rpm_nvr(nvr):
    components = nvr.split('-')
    release = components[-1]
    version = components[-2]
    name    = '-'.join(components[:-2])
    return (name, version, release)


def get_user_home_dir():
    uid = os.getuid()
    try:
        pw = pwd.getpwuid(uid)
    except KeyError, e:
        return None
    home_dir = pw.pw_dir
    return home_dir

def valid_email_address(address):
    match = name_at_domain_re.search(address)
    if match:
        return True
    else:
        return False

def launch_web_browser_on_url(url):
    web_browser_launcher = get_config('helper_apps', 'web_browser_launcher')
    os.spawnl(os.P_NOWAIT, web_browser_launcher, web_browser_launcher, url)

def get_error_from_socket_exception(e):
    args = getattr(e, 'args', None)
    if args:
        errno = args[0]
        strerror = args[1]
    else:
        errno = ERR_SOCKET_ERROR
        strerror = get_strerror(errno)
    return errno, strerror

def assure_file_ownership_permissions(filepath, mode, owner, group=None):
    result = True
    
    if not os.path.exists(filepath):
        try:
            f = open(filepath, "w")
            f.close()
        except Exception, e:
            result = False
            log_program.error("cannot create file %s [%s]", filepath, e.strerror)
    
    try:
        os.chmod(filepath, mode)
    except OSError, e:
        result = False
        log_program.error("cannot chmod %s to %o [%s]", filepath, mode, e.strerror)

    try:
        if isinstance(owner, int):
            uid = owner
        else:
            uid = pwd.getpwnam(owner)[2]

        if group is None: group = owner

        if isinstance(group, int):
            gid = group
        else:
            import grp
            gid = grp.getgrnam(group)[2]

        os.chown(filepath, uid, gid)
    
    except OSError, e:
        result = False
        import grp
        log_program.error("cannot chown %s to %s:%s [%s]", filepath, pwd.getpwuid(uid)[0], grp.getgrgid(gid)[0], e.strerror)

    return result

def abstract(obj):
    import inspect
    method = inspect.getouterframes(inspect.currentframe())[1][3]
    subclass = obj.__class__.__name__
    raise NotImplementedError('%s must be implemented in subclass %s or ancestor class of %s' %
                              (method, subclass, subclass))

#-----------------------------------------------------------------------------

def get_plugin_names(filter_glob=None):
    if filter_glob is None:
        filter_glob = '*'
    else:
        filter_glob = re.sub('.py$','',filter_glob)

    plugin_dir = get_config('plugins','plugin_dir')
    plugin_names = []
    for p in glob.glob(os.path.join(plugin_dir, filter_glob+".py")):
        p = os.path.basename(p)
        if p in ['__init__.py']:
            continue
        plugin_name = os.path.splitext(os.path.basename(p))[0]
        plugin_names.append(plugin_name)
    return plugin_names

def sort_plugins(x,y):
    return x.get_priority()-y.get_priority()
    
def load_plugins(filter_glob=None):
    plugin_dir = get_config('plugins','plugin_dir')
    plugin_base = os.path.basename(plugin_dir)
    plugins = []
    plugin_names = get_plugin_names(filter_glob)
    if debug:
        log_plugin.debug("load_plugins() names=%s", plugin_names)

    # load the parent (e.g. the package containing the submodules), required for python 2.5 and above
    module_name = plugin_base
    plugin_name = '__init__'
    if module_name in sys.modules:
        if debug:
            log_plugin.debug("load_plugins() %s previously imported", module_name)
    else:
        log_plugin.info("importing %s as %s", os.path.join(plugin_dir, plugin_name), module_name)
        try:
            import imp
            mod_fp, mod_path, mod_description = imp.find_module(plugin_name, [plugin_dir])
            mod = imp.load_module(module_name, mod_fp, mod_path, mod_description)
        except Exception:
            log_plugin.exception("failed to load %s plugin", plugin_name)

        if mod_fp:
            mod_fp.close()

    for plugin_name in plugin_names:
        module_name = "%s.%s" % (plugin_base, plugin_name)
        mod = sys.modules.get(module_name)
        if mod is not None:
            if debug:
                log_plugin.debug("load_plugins() %s previously imported", module_name)
            plugins.append(mod.plugin())
            continue
        #log_plugin.info("importing %s as %s", os.path.join(plugin_dir, plugin_name), module_name)
        try:
            import imp
            mod_fp, mod_path, mod_description = imp.find_module(plugin_name, [plugin_dir])
            mod = imp.load_module(module_name, mod_fp, mod_path, mod_description)
            plugins.append(mod.plugin())
        except Exception:
            log_plugin.exception("failed to load %s plugin", plugin_name)

        if mod_fp:
            mod_fp.close()
    
    plugins.sort(sort_plugins)
    return plugins
                
def get_os_environment():
    try:
        myplatform = open(redhat_release_path).readlines()[0].strip()
    except IOError:
        # dist returns (distname, version, id)
        import platform
        myplatform = ' '.join(platform.dist())
        
    # uname returns (sysname, nodename, release, version, machine)
    uname = os.uname()
    kernel_release = uname[2]
    cpu            = uname[4]

    os_desc = "%s %s" % (kernel_release, cpu)
    return (myplatform, os_desc)
    
def get_identity(uid=None):
    if uid is None:
        uid = os.getuid()
    try:
        pwd_entry = pwd.getpwuid(uid)
    except KeyError:
        return None

    username = pwd_entry[0]
    return username

def get_hostname():
    try:
        import socket as Socket
        hostname = Socket.gethostname()
        return hostname
    except Exception, e:
        log_program.warning("cannot lookup hostname: %s", e)
        return None
        
def find_program(prog):
    if os.path.isabs(prog):
        return prog
    basename = os.path.basename(prog)
    search_path = get_config('fix_command','prog_search_path').split(':')
    for d in search_path:
        path = os.path.join(d, basename)
        if os.path.exists(path):
            return path
    return None

def make_database_filepath(name):
    database_dir = get_config('database','database_dir')
    # strip off extension if one was provided
    name = re.sub('\\.xml$', '', name)
    filename = name + '_database.xml'
    filepath = os.path.join(database_dir, filename)
    return filepath

def parse_datetime_offset(text):
    '''The time offset may be specified as a sequence of integer unit pairs.
       Units may be one of year,month,week,day,hour,minute,second and may optionally be plural.
       Example: '2 weeks 1 day' sets the threshold at 15 days.
       '''
    # Note, this regexp anything to follow the unit except an integer
    # thus plural 's', commas, whitespace
    datetime_offset_re = re.compile('(\d+)\s*(year|month|week|day|hour|minute|second)')
    found = False
    days    = 0
    hours   = 0
    minutes = 0
    seconds = 0

    text = text.lower()
    for match in datetime_offset_re.finditer(text):
        if match:
            found = True
            quantity = int(match.group(1))
            unit = match.group(2)

            if unit is not None:
                if unit == 'year':   days    += quantity * 365
                if unit == 'month':  days    += quantity * 31
                if unit == 'week':   days    += quantity * 7
                if unit == 'day':    days    += quantity
                if unit == 'hour':   hours   += quantity
                if unit == 'minute': minutes += quantity
                if unit == 'second': seconds += quantity

    if found:
        td = datetime.timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
        if debug:
            log_cfg.debug("parse_datetime_offset(%s) = time delta %s", text, td)
        return td
    else:
        log_cfg.warning("could not parse datetime offset (%s)", text)
        return None

#------------------------------------------------------------------------------

STDOFFSET = datetime.timedelta(seconds = -time.timezone)
if time.daylight:
    DSTOFFSET = datetime.timedelta(seconds = -time.altzone)
else:
    DSTOFFSET = STDOFFSET

DSTDIFF = DSTOFFSET - STDOFFSET
ZERO = datetime.timedelta(0)
HOUR = datetime.timedelta(hours=1)


# A class capturing the platform's idea of local time.
class LocalTimezone(datetime.tzinfo):

    def utcoffset(self, dt):
        if self._isdst(dt):
            return DSTOFFSET
        else:
            return STDOFFSET

    def dst(self, dt):
        if self._isdst(dt):
            return DSTDIFF
        else:
            return ZERO

    def tzname(self, dt):
        return time.tzname[self._isdst(dt)]

    def _isdst(self, dt):
        tt = (dt.year, dt.month, dt.day,
              dt.hour, dt.minute, dt.second,
              dt.weekday(), 0, -1)
        stamp = time.mktime(tt)
        tt = time.localtime(stamp)
        return tt.tm_isdst > 0

class UTC(datetime.tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return datetime.timedelta(0)

class TimeStamp:
    # class variables
    utc_tz = UTC()
    local_tz = LocalTimezone()

    iso8601_fmt = '%Y-%m-%dT%H:%M:%SZ'
    locale_fmt = '%c'

    def __init__(self, t=None):
        if t is None:
            self._dt = self.now(local=False)
        elif type(t) is StringType:
            self.parse(t)
        elif type(t) is FloatType:
            self._dt = datetime.datetime.fromtimestamp(t, self.utc_tz)
        elif isinstance(t, datetime.datetime):
            self._dt = t
        elif isinstance(t, TimeStamp):
            self._dt = t._dt
        else:
            raise TypeError("must be string, float, datetime, or TimeStamp")
    
    def __cmp__(self, other):
        if isinstance(other, TimeStamp):
            return cmp(self._dt, other._dt)
        else:
            return cmp(self._dt, other)

    def __add__(self, other):
        if isinstance(other, TimeStamp):
            return self._dt + other._dt
        else:
            return self._dt + other

    def __iadd__(self, other):
        if isinstance(other, TimeStamp):
            self._dt += other._dt
        else:
            self._dt += other
        return self

    def __sub__(self, other):
        if isinstance(other, TimeStamp):
            return self._dt - other._dt
        else:
            return self._dt - other

    def __isub__(self, other):
        if isinstance(other, TimeStamp):
            self._dt -= other._dt
        else:
            self._dt -= other
        return self

    def now(self, local=False):
        if local:
            return datetime.datetime.now(self.local_tz)
        else:
            return datetime.datetime.now(self.utc_tz)
    
    def local(self):
        return self._dt.astimezone(self.local_tz)

    def __str__(self):
        return self.format(self.iso8601_fmt, local=False)

    def parse(self, str):
        (year, month, day, hour, minute, second, weekday, yearday, dst) = \
               time.strptime(str, self.iso8601_fmt)
        self._dt = datetime.datetime(year, month, day, hour, minute, second,
                                     0, self.utc_tz)
        return self._dt

    def add(self,days=0, hours=0, minutes=0, seconds=0):
        self._dt += datetime.timedelta(days=days, hours=hours,
                                       minutes=minutes, seconds=seconds)
        
    def in_future(self):
        now = self.now()
        if now < self._dt:
            return True
        else:
            return False

    def in_past(self):
        now = self.now()
        if now >= self._dt:
            return True
        else:
            return False

    def format(self, fmt=None, local=True):
        if fmt is None:
            fmt = self.locale_fmt
        if local:
            return self.local().strftime(fmt)
        else:
            return self._dt.strftime(fmt)
        
#------------------------------------------------------------------------------

class Retry(gobject.GObject):
    '''
    A class which schedules attempts until one succeeds.

    Intervals are expressed as floating point seconds.

    The retry attempt will be scheduled in the future based on the
    retry_interval which may be either a number of seconds or a
    callable object returning the number of seconds. The callable
    form of the retry_interval is useful when the interval should be
    adjusted based on prior history or other external factors,
    e.g. backing off the frequency of the retry attempts if initial
    attempts fail.

    The retry callback should return False if the attempt fails, in
    which case it will be scheduled again in the future based on the
    current value obtained from the retry_interval. If the retry
    callback returns True it indicates the retry attempt succeeded and
    no more attempts will be made.

    Retry's are started with the start() method and continues until
    the retry callback returns True or the stop() method is called. It
    is always safe to call stop() even if a retry is not pending.

    The retry callback, user_data and notify_interval may be specified
    in either the class init() or in the start() method for convenience.

    If notify_interval is set a 'pending_retry' signal will be emitted
    every time the notification interval elapses, this provides a
    countdown till the next retry attempt.

    The signature of the retry callback is: callback(retry_obj, user_data)

    The signature of the pending_retry signal handler is: callback(retry_obj, seconds_pending, user_data)

    The signature of the retry interval function is: interval(retry_obj, user_data)
    '''
    __gsignals__ = {
        'pending_retry':                # callback(retry_object, seconds_pending, user_data)
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_FLOAT, gobject.TYPE_PYOBJECT,)),
        }

    def __init__(self, callback, retry_interval, user_data=None, notify_interval=None):
        gobject.GObject.__init__(self)
        self.callback = callback
        self.retry_interval = retry_interval
        self.user_data = user_data
        self.failed_attempts = 0                # how many times retry has been attempted but failed
        self.notify_interval = notify_interval  # how often pending_retry signal is emitted
        self.trigger_time = None                # time in future when retry is attempted
        self.timeout_id = None                  # alarm timeout id
    
    def stop(self):
        if self.timeout_id is not None:
            gobject.source_remove(self.timeout_id)
            self.timeout_id = None

    def start(self,  retry_interval=None, user_data=None, notify_interval=None):
        if retry_interval is not None:
            self.retry_interval = retry_interval
        if user_data is not None:
            self.user_data = user_data
        if notify_interval is not None:
            self.notify_interval = notify_interval

        self.stop()
        self.failed_attempts = 0
        self._schedule_alarm(True)

    def _schedule_alarm(self, new_retry=False):
        now = time.time()
        if new_retry:
            self.trigger_time = now + self._get_retry_interval()
        seconds_pending = self.trigger_time - now
        if self.notify_interval:
            self.emit('pending_retry', seconds_pending, self.user_data)
            alarm_time = min(self.notify_interval, seconds_pending)
        else:
            alarm_time = seconds_pending
        self.timeout_id = gobject.timeout_add(int(alarm_time*1000), self._alarm_callback)

    def _alarm_callback(self):
        self.timeout_id = None
        now = time.time()
        seconds_pending = self.trigger_time - now

        # If seconds_pending is less than 0 we've gone past the
        # trigger point so attempt a retry because its overdue. If
        # seconds_pending is 0 we've exactly hit the trigger point
        # (not likely). If seconds_pending is positive the trigger
        # point is in the future, however, due to (minor) scheduling
        # inaccuracies if seconds_pending is a small positive number
        # we assume this alarm is triggering the retry attempt even
        # though it is slightly in the future.

        if seconds_pending <= 0.005:
            self._attempt_retry()
        else:
            self._schedule_alarm()
        return False

    def _attempt_retry(self):
        if self.callback(self, self.user_data):
            self.stop()
        else:
            self.failed_attempts += 1
            self._schedule_alarm(True)

    def _get_retry_interval(self):
        interval_type = type(self.retry_interval)
        if interval_type is MethodType or interval_type is FunctionType:
            return self.retry_interval(self, self.user_data)
        return self.retry_interval

gobject.type_register(Retry)

#-----------------------------------------------------------------------------

    

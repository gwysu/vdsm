#!/usr/bin/python
# Copyright 2012 by IBM
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#
# Refer to the README and COPYING files for full details of the license
#

import os
import sys
import glob
import logging
import subprocess
import traceback
import tempfile
import filecmp
import shutil
import re
import pwd
import grp

from vdsm.tool import vdsm_tool_expose
from vdsm import constants
from vdsm.config import config


VDSM_BIN = os.path.join(constants.P_VDSM, 'vdsm')
VCONF = os.path.join(constants.P_VDSM_CONF, 'vdsm.conf')
GET_CONF_ITEM = os.path.join(constants.P_VDSM, 'get-conf-item')
PID_FILE = os.path.join(constants.P_VDSM_RUN, 'vdsmd.pid')
RESPAWN = os.path.join(constants.P_VDSM, 'respawn')
RESPAWN_PID_FILE = os.path.join(constants.P_VDSM_RUN, 'respawn.pid')
VDSM_RUN_DIR = constants.P_VDSM_RUN
POOLS_DIR = constants.P_VDSM_POOL
HOOKS = os.path.join(constants.P_VDSM, 'hooks.pyc')
EX_VDSM_RESTORE_NET_CONFIG = os.path.join(constants.P_VDSM,
                                          'vdsm-restore-net-config')


EX_CHKCONFIG = constants.EXT_CHKCONFIG
EX_DF = constants.EXT_DF
EX_IFCONFIG = constants.EXT_IFCONFIG
EX_INITCTL = constants.EXT_INITCTL
EX_MODPROBE = constants.EXT_MODPROBE
EX_NETSTAT = constants.EXT_NETSTAT
EX_OPENSSL = constants.EXT_OPENSSL
EX_PERSIST = constants.EXT_PERSIST
EX_PIDOF = constants.EXT_PIDOF
EX_PYTHON = constants.EXT_PYTHON
EX_RESTORECON = constants.EXT_RESTORECON
EX_RPM = constants.EXT_RPM
EX_SEMANAGE = constants.EXT_SEMANAGE
EX_SERVICE = constants.EXT_SERVICE
EX_SETSEBOOL = constants.EXT_SETSEBOOL
EX_SYSCTL = constants.EXT_SYSCTL
EX_UNPERSIST = constants.EXT_UNPERSIST

BY_VDSM = '# by vdsm'
VDSM_VER = '4.9.6'
VDSM_SECTION_START = '## beginning of configuration section %s' % BY_VDSM
VDSM_SECTION_END = '## end of configuration section %s' % BY_VDSM

VDSM_SYSCTL_START = '# VDSM section begin'
VDSM_SYSCTL_END = '# VDSM section end'
VDSM_SYSCTL_VER = '%s (v.1)' % VDSM_SYSCTL_START

LCONF = '/etc/libvirt/libvirtd.conf'
QCONF = '/etc/libvirt/qemu.conf'
LDCONF = '/etc/sysconfig/libvirtd'
QLCONF = '/etc/libvirt/qemu-sanlock.conf'

DEFAULT_LOG = '# vdsm \n\
/var/log/libvirtd.log {\n\
    rotate 100\n\
    missingok\n\
    copytruncate\n\
    size 15M\n\
    compress\n\
    compresscmd /usr/bin/xz\n\
    uncompresscmd /usr/bin/unxz\n\
    compressext .xz\n\
}\n\
# end vdsm\n'


def _exec_command(argv):
    """
    This function executes a given shell command.
    """

    out = ''
    err = ''
    rc = 0
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        rc = p.returncode
    except:
        logging.error(traceback.format_exc())
    return (out, err, rc)


def _call(*args, **kwargs):
    """
    Call a function from /etc/init.d/functions.
    """
    cmd = 'SYSTEMCTL_SKIP_REDIRECT=true source /etc/init.d/functions;'
    for (k, v) in kwargs.items():
        cmd += '%s=%s ' % (k, v)
    for arg in args:
        cmd += ' ' + arg
    try:
        rc = subprocess.call(cmd, shell=True)
    except OSError, e:
        print >> sys.stderr, "Execution failed:", e

    return rc


def _print_success_msg(msg):
    subprocess.call(['echo', '-n', msg])
    _call('success')
    subprocess.call(['echo'])


def _print_failure_msg(msg):
    subprocess.call(['echo', '-n', msg])
    _call('failure')
    subprocess.call(['echo'])


def _remove_section(file, start, end):
    lines = []
    with open(file) as f:
        skip = False
        for line in f.readlines():
            if skip:
                if line.startswith(end):
                    skip = False
                continue
            if line.startswith(start):
                skip = True
                continue
                skip = False
            lines.append(line)
    return lines


def _remove_vdsm_conf(file):
    """
    Remove configuration created by vdsm (old "# by vdsm" and the new format)
    Argument: configuration file that will be inspected
    """

    lines = []
    with open(file) as f:
        skip = False
        for line in f.readlines():
            if skip:
                if line.startswith(VDSM_SECTION_END):
                    skip = False
                continue
            if line.startswith(VDSM_SECTION_START):
                skip = True
                continue
                skip = False
            if line.endswith('%s\n' % BY_VDSM):
                continue
            lines.append(line)

    with open(file, "w") as f:
        f.writelines(lines)


def _set_vdsm_conf(file, items):
    with open(file) as f:
        lines = f.readlines()
    with open(file, 'a') as f:
        for line in lines:
            for key in items.keys():
                if re.search('^\s*%s\s*=' % key, line):
                    continue
                f.write('%s=%s\n' % (key, items[key]))


def _find_vdsm_conf(file):
    with open(file) as f:
        str = f.read()
        if re.search(VDSM_VER, str):
            return True
    return False


def _get_config_item(file, section, item, default):
    config.read(file)
    try:
        return config.get(section, item)
    except:
        return default


def _is_ovirt():
    """
    This function checks if current machine runs ovirt platform.
    """
    if os.path.exists('/etc/rhev-hypervisor-release'):
        return True
    elif not len(glob.glob('/etc/ovirt-node-*-release')) == 0:
        return True
    else:
        return False


def _is_coredump():
    enable = _get_config_item(VCONF, 'vars', 'core_dump_enable', 'false')
    if enable == 'true':
        return True
    else:
        return False


def _is_port_taken():
    port = _get_config_item(VCONF, 'addresses', 'management_port', '')
    if len(port) == 0:
        _print_failure_msg('vdsm: management_port not found in %s' % VCONF)
        return True
    ip = _get_config_item(VCONF, 'addresses', 'management_ip', '0.0.0.0')
    out = _exec_command([EX_NETSTAT, '-ntl'])[0]
    if re.search('%s:%s' % (ip, port), out):
        _print_failure_msg('vdsm: port %s already bound' % port)
        return True
    return False


def _mk_vdsm_path(path, mode=None, user=None, group=None, restorecon=False):
    if not os.path.exists(path):
        os.makedirs(path)
        if mode:
            os.chmod(path, mode)
        if user and group:
            uid = pwd.getpwnam(user)[2]
            gid = grp.getgrnam(group)[2]
            os.chown(path, uid, gid)
        if restorecon:
            _exec_command([EX_RESTORECON, path])


def _get_libvirt_conf_item(file, key):
    result = []
    with open(file) as f:
        for line in f.readlines():
            if re.search('^\s*%s\s*=' % key, line):
                result.append(line)
    if len(result):
        s = re.search('^\s*%s\s*=\s*(.*\S)\s*#.*' % key, result[-1])
        if s:
            return s.group(1)
    return None


def _is_conf_conflicting():
    ssl = _get_config_item(VCONF, 'var', 'ssl', 'true')
    if ssl == 'true':
        return False
    listen_tcp = _get_libvirt_conf_item(LCONF, 'listen_tcp')
    auth_tcp = _get_libvirt_conf_item(LCONF, 'auth_tcp')
    spice_tls = _get_libvirt_conf_item(QCONF, 'spice_tls')
    if listen_tcp == '1' and auth_tcp == '"none"' and spice_tls == 0:
        return False
    else:
        print "conflicting vdsm and libvirt tls configuration."
        print "vdsm.conf with ssl=False requires libvirt with:"
        print "listen_tcp=1, auth_tcp=\"none\" and spice_tls=0."
        return True


def _shutdown_conflicting_srv():
    services = ['libvirt-guests']
    for srv in services:
        _exec_command([EX_CHKCONFIG, 'srv', 'off'])
        rc = _exec_command([EX_SERVICE, srv, 'status'])[2]
        if rc == 0:
            if srv == 'libvirt-guests':
                if os.path.exists('/var/lock/subsys/libvirt-guests'):
                    os.unlink('/var/lock/subsys/libvirt-guests')
            else:
                _exec_command([EX_SERVICE, srv, 'stop'])
    return 0


def _upstart_libvirt():
    """
    This fucntion test if the "/sbin/initctl" can be executed.
    """

    return os.access('/sbin/initctl', os.X_OK)


def _start_needed_srv():
    services = ['iscsid', 'multipathd', 'ntpd', 'wdmd', 'sanlock']
    for srv in services:
        rc1 = _exec_command([EX_SERVICE, srv, 'status'])[2]
        if rc1 != 0:
            print 'Starting %s...' % srv
            rc2 = _exec_command([EX_SERVICE, srv, 'start'])[2]
            if rc2 != 0:
                _print_failure_msg('vdsm: Dependent %s failed to start' % srv)
                return rc2
    _exec_command([EX_SERVICE, 'iscsid', 'force-start'])
    return 0


def _is_lo_up():

    env = os.environ.copy()
    env.update({"LC_ALL": "C"})
    p = subprocess.Popen([EX_IFCONFIG, 'lo'], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env)
    out = p.communicate()[0]
    if re.search('UP', out) is None:
        _print_failure_msg('VDSMD: lo interface is down, can\'t run !')
        with open('/dev/kmsg', 'a') as f:
            f.write('VDSMD: lo interface is down, can\'t run !\n')
        return False
    else:
        return True


def _free_space(path):
    p = subprocess.Popen([EX_DF, '-P', path], stdout=subprocess.PIPE)
    out = p.communicate()[0]
    lastline = out.splitlines()[-1]
    available = lastline.split()[3]
    return long(available)


def _is_space_available():
    if _free_space("/var/log/vdsm") < 10000:
        _print_failure_msg("vdsm: low log space")
        return False
    else:
        return True


def _is_bond_dev_available(bonddev):
    devs = '/sys/class/net/bonding_masters'
    bond = []
    with open(devs, 'r') as f:
        bond = f.read().strip('\n').split(' ')
    if bonddev in bond:
        return True
    else:
        return False


def _load_needed_modules():
    _exec_command([EX_MODPROBE, 'tun'])
    _exec_command([EX_MODPROBE, 'bonding'])
    # RHEV-M currently assumes that all bonding devices pre-exist
    devs = '/sys/class/net/bonding_masters'
    bond = ['bond0', 'bond1', 'bond2', 'bond3', 'bond4']
    for bonddev in bond:
        if not _is_bond_dev_available(bonddev):
            with open(devs, 'w') as f:
                f.write('+%s\n' % bonddev)
    _exec_command([EX_MODPROBE, '8021q'])


def _is_already_running():
    if (_call('pidofproc', '-p', RESPAWN_PID_FILE, '>/dev/null') == 0 or
        _call('pidofproc', '-p', PID_FILE, VDSM_BIN, '>/dev/null') == 0):
        _print_success_msg('vdsm: already running')
        return True
    else:
        return False


def _validate_libvirt_certs():
    """ Validate vdsmcert.pem against cacert.pem """
    print "checking certs.."
    uid = pwd.getpwnam('vdsm')[2]
    gid = pwd.getpwnam('vdsm')[3]
    basepath = '/etc/pki/vdsm/certs'
    cacertpath = '%s/cacert.pem' % basepath
    vdsmcertpath = '%s/vdsmcert.pem' % basepath

    out = _exec_command([EX_OPENSSL, 'verify', cacertpath, vdsmcertpath])
    if out != '%s: OK' % vdsmcertpath:
        for file in os.listdir(basepath):
            out = _exec_command([EX_OPENSSL, 'verify', '%s/file' % basepath,
                                 vdsmcertpath])
            if out == '%s: OK' % vdsmcertpath:
                _exec_command([EX_UNPERSIST, cacertpath, '1'])
                os.unlink(cacertpath)
                shutil.copy('%s/file' % basepath, cacertpath)
                os.chown(cacertpath, uid, gid)
                os.chmod(cacertpath, 0600)
                _exec_command([EX_PERSIST, cacertpath, '1'])
                break


def _configure_libvirt(force):
    conf = [LCONF, QCONF, LDCONF, QLCONF]
    lconfitems = {}
    qconfitems = {}
    ldconfitems = {}
    qlconfitems = {}

    # Do not configure ovirt nodes before registration
    if _is_ovirt():
        if not os.path.exists('/etc/pki/vdsm/certs/vdsmcert.pem'):
            _print_failure_msg('vdsm: Missing certificates, '
                               'vdsm not registered')
            return 6
        _validate_libvirt_certs()

    # do not reconfigure, return 0, so that vdsm start can continue.
    if not force:
        if (_find_vdsm_conf(LCONF) and
            _find_vdsm_conf(QCONF) and
            _find_vdsm_conf(LDCONF) and
            _find_vdsm_conf(QLCONF)):
            _print_success_msg('vdsm: libvirt already configured for vdsm')
            return 0

    print "Configuring libvirt for vdsm..."
    # Remove a previous configuration (if present)
    for file in conf:
        _remove_vdsm_conf(file)
    # Write to all conf files the *initial* message of vdsm changes
    for file in conf:
        with open(file, 'a') as f:
            f.write('%s-%s\n' % (VDSM_SECTION_START, VDSM_VER))

    lconfitems['listen_addr'] = '"0"'
    lconfitems['unix_sock_group'] = '"kvm"'
    lconfitems['unix_sock_rw_perms'] = '"0770"'
    lconfitems['auth_unix_rw'] = '"sasl"'
    lconfitems['save_image_format'] = '"lzop"'

    # FIXME until we are confident with libvirt integration,
    # let us have a verbose log
    lconfitems['log_outputs'] = '"1:file:/var/log/libvirtd.log"'
    lconfitems['log_filters'] = '"1:libvirt 3:event 3:json 1:util 1:qemu"'

    ssl = _get_config_item(VCONF, 'vars', 'ssl', 'true')
    if ssl == 'true':
        qconfitems['spice_tls'] = '1'
    else:
        qconfitems['spice_tls'] = '0'
    ldconfitems['LIBVIRTD_ARGS'] = '--listen'
    ldconfitems['DAEMON_COREFILE_LIMIT'] = 'unlimited'
    # If the ssl flag is set, update the libvirt and qemu
    # configuration files with the location for
    # certificates and permissions.
    cacertpath = '/etc/pki/vdsm/certs/cacert.pem'
    vdsmcertpath = '/etc/pki/vdsm/certs/vdsmcert.pem'
    vdsmkeypath = os.path.join(constants.P_VDSM_KEYS, 'vdsmkey.pem')
    if (os.path.exists(cacertpath) and
            os.path.exists(vdsmcertpath) and
            os.path.exists(vdsmkeypath) and
            ssl == 'true'):
        lconfitems['ca_file'] = '"%s"' % cacertpath
        lconfitems['cert_file'] = '"%s"' % vdsmcertpath
        lconfitems['key_file'] = '"%s"' % vdsmkeypath
        qconfitems['spice_tls_x509_cert_dir'] = '"/etc/pki/vdsm/libvirt-spice"'
    else:
        lconfitems['auth_tcp'] = '"none"'
        lconfitems['listen_tcp'] = '1'
        lconfitems['listen_tls'] = '0'

    # Configuring sanlock
    qlconfitems['lock_manager'] = '"sanlock"'
    qlconfitems['auto_disk_leases'] = '0'
    qlconfitems['require_lease_for_disks'] = '0'

    _set_vdsm_conf(LCONF, lconfitems)
    _set_vdsm_conf(QCONF, qconfitems)
    _set_vdsm_conf(LDCONF, ldconfitems)
    _set_vdsm_conf(QLCONF, qlconfitems)

    # Write to all conf files the *end* message of vdsm changes
    for file in conf:
        with open(file, 'a') as f:
            f.write('%s-%s' % (VDSM_SECTION_END, VDSM_VER))

    lnetwork = '/etc/libvirt/qemu/networks/autostart/default.xml'
    if os.path.exists(lnetwork):
        os.unlink(lnetwork)

    llogr = '/etc/logrotate.d/libvirtd'
    lines = _remove_section(llogr, 'vdsm', '# end vdsm')
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(DEFAULT_LOG)
        f.writelines(lines)
    st = os.stat(llogr)
    os.rename(f.name, llogr)
    os.chmod(llogr, st.st_mode)
    _exec_command([EX_RESTORECON, llogr])
    if _is_ovirt():
        try:
            from ovirtnode import ovirtfunctions
        except ImportError:
            _print_failure_msg('Can\'t import ovirt functions')
            return 5
        conf.append(llogr)
        for file in conf:
            ovirtfunctions.ovirt_store_config(file)

    # vdsm makes extensive use of nfs-exported images
    with tempfile.NamedTemporaryFile() as f:
        f.write('virt_use_nfs=1')
        f.write('virt_use_sanlock=1')
        _exec_command([EX_SEMANAGE, 'boolean', '-m', '-S', 'targeted',
                       '-F', f.name])
    _exec_command([EX_SETSEBOOL, 'virt_use_nfs', 'on'])
    if _upstart_libvirt():
        _exec_command([EX_INITCTL, 'restart', 'libvirtd'])


def _configure_sysctl():
    str = ''
    sysconf = '/etc/sysctl.conf'
    with open(sysconf) as f:
        str = f.read()
    if re.search(VDSM_SYSCTL_START, str) is None:
        print "Configuring sysctl for vdsm..."
        lines = _remove_section(sysconf, VDSM_SYSCTL_START, VDSM_SYSCTL_END)
        with open('/etc/sysctl.conf.vdsm', 'w') as f:
            f.writelines(lines)
            f.write('%s\n' % VDSM_SYSCTL_VER)
            f.write('vm.dirty_ratio = 5\n')
            f.write('vm.dirty_background_ratio = 2\n')
            f.write('%s\n' % VDSM_SYSCTL_VER)
        os.rename('/etc/sysctl.conf.vdsm', sysconf)
        rc = _exec_command([EX_SYSCTL, '-q', '-p', sysconf])[2]
        return rc
    return 0


def _reconfigure(force):
    _configure_libvirt(force)
    rc = _configure_sysctl()
    return rc


def _stop_libvirtd_sysv():
    """
        Stop libvirt SysV service if we intend to configure upstart
    """

    if(_upstart_libvirt()):
        _exec_command([EX_CHKCONFIG, 'libvirtd', 'off'])
        _exec_command([EX_SERVICE, 'libvirtd', 'stop'])


def _start_libvirtd():
    """
    Start libvirt daemon
    """
    result = []
    if not _upstart_libvirt():
        rc = _exec_command([EX_SERVICE, 'libvirtd', 'start'])[2]
        return rc
    out = _exec_command([EX_RPM, '-ql', 'libvirt'])[0]
    for line in out.splitlines():
        s = re.serarch('libvirtd.start', out)
        if s:
            result.append(s.group())

    target = '/etc/init/libvirtd.conf'
    if not filecmp.cmp(result[-1], target):
        shutil.copy2(result[-1], target)
        _exec_command([EX_INITCTL, 'reload-configuration'])
    out, err, rc = _exec_command([EX_INITCTL, 'start', 'libvirtd'])
    if rc == 0 or re.search('already running', result[-1]) is not None:
        return 0
    else:
        print >> sys.stderr, err
        return 1


@vdsm_tool_expose('vdsm-start')
def vdsm_start():
    """
    Start vdsm
    """

    env = {}
    _exec_command([EX_PYTHON, HOOKS, 'before_vdsm_start'])
    _shutdown_conflicting_srv()
    _stop_libvirtd_sysv()
    rc = _reconfigure(False)
    if rc != 0:
        _print_failure_msg('vdsm: failed to reconfigure libvirt')
        return rc
    rc = _start_needed_srv()
    if rc == 0:
        rc = _start_libvirtd()
    if rc != 0:
        _print_failure_msg('vdsm: one of the dependent services did not start')
        return rc
    _exec_command([EX_VDSM_RESTORE_NET_CONFIG])
    _load_needed_modules()
    # make data center
    path = _get_config_item(VCONF, 'irs', 'repository', '/rhev/')
    _mk_vdsm_path(path, None, 'vdsm', 'kvm')
    # make log core path
    path = '/var/log/core'
    _mk_vdsm_path(path, 01777)
    # make dom backup path
    path = '/var/log/vdsm/backup'
    _mk_vdsm_path(path, None, 'vdsm', 'kvm')
    # make run path
    runpath = [VDSM_RUN_DIR, POOLS_DIR]
    for path in runpath:
        _mk_vdsm_path(path, 0755, 'vdsm', 'kvm', True)
    os.chmod('/dev/shm', 01777)
    if _is_coredump():
        dumppath = '/var/log/core/core.%p.%t.dump'
        pattern = '/proc/sys/kernel/core_pattern'
        env['DAEMON_COREFILE_LIMIT'] = 'unlimited'
        with open(pattern, 'w') as f:
            f.write('%s\n' % dumppath)
    if _is_already_running():
        return 0
    if (not _is_space_available() or not _is_lo_up() or
        _is_port_taken() or _is_conf_conflicting()):
        return 1
    print "Starting up vdsm daemon: "
    env['NICELEVEL'] = _get_config_item(VCONF, 'var', 'vdsm_nice', '-5')
    env['LIBVIRT_LOG_FILTERS'] = _get_config_item(VCONF, 'var',
                                'libvirt_log_filters', '"1:libvirt 1:remote"')
    env['LIBVIRT_LOG_OUTPUTS'] = _get_config_item(VCONF, 'var',
                                'libvirt_log_outputs',
                                '"1:file:/var/log/vdsm/libvirt.log"')
    env['LC_ALL'] = 'C'
    rc = _call('daemon', '--user=vdsm',
              '%s --minlifetime 10 --daemon --masterpid %s %s' %
              (RESPAWN, RESPAWN_PID_FILE, VDSM_BIN), **env)
    if rc == 0:
        _print_success_msg('vdsm start')
        with open('/var/lock/subsys/vdsmd', 'w'):
            pass
    else:
        _print_failure_msg('vdsm start')


@vdsm_tool_expose('vdsm-stop')
def vdsm_stop():
    """
    Stop vdsm.
    """
    print "Shutting down vdsm daemon: "
    rc = 0
    if _call('killproc', '-p', RESPAWN_PID_FILE) == 0:
        _print_success_msg('vdsm watchdog stop')
    if _call('pidofproc', '-p', PID_FILE, '>/dev/null') != 0:
        _print_failure_msg('vdsm: not running')
    else:
        rc = _call('killproc', '-p', PID_FILE, '-d', '2')
        if rc == 0:
            _print_success_msg('vdsm stop')
            try:
                os.unlink('/var/lock/subsys/vdsmd')
            except OSError:
                pass
        else:
            _print_failure_msg('vdsm stop')
    _exec_command([EX_PYTHON, HOOKS, 'after_vsm_stop'])
    return rc


@vdsm_tool_expose('vdsm-status')
def vdsm_status():
    """
    Get vdsm running status.
    """

    rc = _call('pidofproc', '-p', PID_FILE, VDSM_BIN, '>/dev/null')
    if rc == 0:
        print 'VDS daemon server is running'
    else:
        if _call('pidofproc', '-p', RESPAWN_PID_FILE, '>dev/null') == 0:
            print 'VDS daemon is not running, but its watchdog is'
        else:
            print 'VDS daemon is not running'
    return rc


@vdsm_tool_expose('vdsm-condrestart')
def vdsm_condrestart():
    """
    Restart vdsm conditionally.
    """

    rc = _call('pidofproc', '-p', PID_FILE, VDSM_BIN, '>/dev/null')
    if rc == 0:
        rc = vdsm_stop()
        if rc == 0:
            rc = vdsm_start()
    return rc


@vdsm_tool_expose('vdsm-try-restart')
def vdsm_try_restart():
    """
    Try to restart vdsm.
    """

    rc = vdsm_stop()
    if rc == 0:
        rc = vdsm_start()
    return rc


@vdsm_tool_expose('vdsm-restart')
def vdsm_restart():
    """
    Restart vdsm.
    """

    vdsm_stop()
    return vdsm_start()


@vdsm_tool_expose('vdsm-reconfigure')
def vdsm_reconfigure(args=None):
    """
    Reconfigure vdsm.
    """

    if args == 'force':
        _reconfigure(True)
    else:
        _reconfigure(False)

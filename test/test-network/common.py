# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
import errno
import os
import pathlib
import re
import shutil
import signal
import subprocess
import time
import unittest


network_unit_dir = '/run/systemd/network'
networkd_conf_dropin_dir = '/run/systemd/networkd.conf.d'
networkd_ci_temp_dir = '/run/networkd-ci'
udev_rules_dir = '/run/udev/rules.d'

dnsmasq_pid_file = '/run/networkd-ci/test-dnsmasq.pid'
dnsmasq_log_file = '/run/networkd-ci/test-dnsmasq.log'
dnsmasq_lease_file = '/run/networkd-ci/test-dnsmasq.lease'

isc_dhcpd_pid_file = '/run/networkd-ci/test-isc-dhcpd.pid'
isc_dhcpd_lease_file = '/run/networkd-ci/test-isc-dhcpd.lease'

systemd_lib_paths = ['/usr/lib/systemd', '/lib/systemd']
which_paths = ':'.join(systemd_lib_paths + os.getenv('PATH', os.defpath).lstrip(':').split(':'))

networkd_bin = shutil.which('systemd-networkd', path=which_paths)
resolved_bin = shutil.which('systemd-resolved', path=which_paths)
timesyncd_bin = shutil.which('systemd-timesyncd', path=which_paths)
udevd_bin = shutil.which('systemd-udevd', path=which_paths)
wait_online_bin = shutil.which('systemd-networkd-wait-online', path=which_paths)
networkctl_bin = shutil.which('networkctl', path=which_paths)
resolvectl_bin = shutil.which('resolvectl', path=which_paths)
timedatectl_bin = shutil.which('timedatectl', path=which_paths)
udevadm_bin = shutil.which('udevadm', path=which_paths)

networkctl_cmd = []
resolvectl_cmd = []
timedatectl_cmd = []
udevadm_cmd = []
wait_online_cmd = []

use_valgrind = False
valgrind_cmd = ''
enable_debug = True
env = {}
wait_online_env = {}
asan_options = None
lsan_options = None
ubsan_options = None
with_coverage = False

active_units = []
protected_links = {
    'erspan0',
    'gre0',
    'gretap0',
    'ifb0',
    'ifb1',
    'ip6_vti0',
    'ip6gre0',
    'ip6tnl0',
    'ip_vti0',
    'lo',
    'sit0',
    'tunl0',
}
saved_routes = None
saved_ipv4_rules = None
saved_ipv6_rules = None
saved_timezone = None

def rm_f(path):
    if os.path.exists(path):
        os.remove(path)

def rm_rf(path):
    shutil.rmtree(path, ignore_errors=True)

def cp(src, dst):
    shutil.copy(src, dst)

def cp_r(src, dst):
    shutil.copytree(src, dst, copy_function=shutil.copy)

def mkdir_p(path):
    os.makedirs(path, exist_ok=True)

def touch(path):
    pathlib.Path(path).touch()

# pylint: disable=R1710
def check_output(*command, **kwargs):
    # This checks the result and returns stdout (and stderr) on success.
    command = command[0].split() + list(command[1:])
    ret = subprocess.run(command, check=False, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    if ret.returncode == 0:
        return ret.stdout.rstrip()
    # When returncode != 0, print stdout and stderr, then trigger CalledProcessError.
    print(ret.stdout)
    ret.check_returncode()

def call(*command, **kwargs):
    # This returns returncode. stdout and stderr are merged and shown in console
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stderr=subprocess.STDOUT, **kwargs).returncode

def call_quiet(*command, **kwargs):
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs).returncode

def run(*command, **kwargs):
    # This returns CompletedProcess instance.
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)

def is_module_available(*module_names):
    for module_name in module_names:
        lsmod_output = check_output('lsmod')
        module_re = re.compile(rf'^{re.escape(module_name)}\b', re.MULTILINE)
        if not module_re.search(lsmod_output) and call_quiet('modprobe', module_name) != 0:
            return False
    return True

def expectedFailureIfModuleIsNotAvailable(*module_names):
    def f(func):
        return func if is_module_available(*module_names) else unittest.expectedFailure(func)

    return f

def expectedFailureIfERSPANv0IsNotSupported():
    # erspan version 0 is supported since f989d546a2d5a9f001f6f8be49d98c10ab9b1897 (v5.8)
    def f(func):
        rc = call_quiet('ip link add dev erspan99 type erspan seq key 30 local 192.168.1.4 remote 192.168.1.1 erspan_ver 0')
        remove_link('erspan99')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfERSPANv2IsNotSupported():
    # erspan version 2 is supported since f551c91de262ba36b20c3ac19538afb4f4507441 (v4.16)
    def f(func):
        rc = call_quiet('ip link add dev erspan99 type erspan seq key 30 local 192.168.1.4 remote 192.168.1.1 erspan_ver 2')
        remove_link('erspan99')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyPortRangeIsNotAvailable():
    def f(func):
        rc = call_quiet('ip rule add from 192.168.100.19 sport 1123-1150 dport 3224-3290 table 7')
        call_quiet('ip rule del from 192.168.100.19 sport 1123-1150 dport 3224-3290 table 7')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyIPProtoIsNotAvailable():
    def f(func):
        rc = call_quiet('ip rule add not from 192.168.100.19 ipproto tcp table 7')
        call_quiet('ip rule del not from 192.168.100.19 ipproto tcp table 7')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyUIDRangeIsNotAvailable():
    def f(func):
        supported = False
        if call_quiet('ip rule add from 192.168.100.19 table 7 uidrange 200-300') == 0:
            ret = run('ip rule list from 192.168.100.19 table 7')
            supported = ret.returncode == 0 and 'uidrange 200-300' in ret.stdout
            call_quiet('ip rule del from 192.168.100.19 table 7 uidrange 200-300')
        return func if supported else unittest.expectedFailure(func)

    return f

def expectedFailureIfNexthopIsNotAvailable():
    def f(func):
        rc = call_quiet('ip nexthop list')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfRTA_VIAIsNotSupported():
    def f(func):
        call_quiet('ip link add dummy98 type dummy')
        call_quiet('ip link set up dev dummy98')
        call_quiet('ip route add 2001:1234:5:8fff:ff:ff:ff:fe/128 dev dummy98')
        rc = call_quiet('ip route add 10.10.10.10 via inet6 2001:1234:5:8fff:ff:ff:ff:fe dev dummy98')
        remove_link('dummy98')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfAlternativeNameIsNotAvailable():
    def f(func):
        call_quiet('ip link add dummy98 type dummy')
        supported = \
            call_quiet('ip link prop add dev dummy98 altname hogehogehogehogehoge') == 0 and \
            call_quiet('ip link show dev hogehogehogehogehoge') == 0
        remove_link('dummy98')
        return func if supported else unittest.expectedFailure(func)

    return f

def expectedFailureIfNetdevsimWithSRIOVIsNotAvailable():
    def f(func):
        def finalize(func, supported):
            call_quiet('rmmod netdevsim')
            return func if supported else unittest.expectedFailure(func)

        call_quiet('rmmod netdevsim')
        if call_quiet('modprobe netdevsim') != 0:
            return finalize(func, False)

        try:
            with open('/sys/bus/netdevsim/new_device', mode='w', encoding='utf-8') as f:
                f.write('99 1')
        except OSError:
            return finalize(func, False)

        return finalize(func, os.path.exists('/sys/bus/netdevsim/devices/netdevsim99/sriov_numvfs'))

    return f

# pylint: disable=C0415
def compare_kernel_version(min_kernel_version):
    try:
        import platform

        from packaging import version
    except ImportError:
        print('Failed to import either platform or packaging module, assuming the comparison failed')
        return False

    # Get only the actual kernel version without any build/distro/arch stuff
    # e.g. '5.18.5-200.fc36.x86_64' -> '5.18.5'
    kver = platform.release().split('-')[0]

    return version.parse(kver) >= version.parse(min_kernel_version)

def udev_reload():
    check_output(*udevadm_cmd, 'control', '--reload')

def copy_network_unit(*units, copy_dropins=True):
    """
    Copy networkd unit files into the testbed.

    Any networkd unit file type can be specified, as well as drop-in files.

    By default, all drop-ins for a specified unit file are copied in;
    to avoid that specify dropins=False.

    When a drop-in file is specified, its unit file is also copied in automatically.
    """
    has_link = False
    mkdir_p(network_unit_dir)
    for unit in units:
        if copy_dropins and os.path.exists(os.path.join(networkd_ci_temp_dir, unit + '.d')):
            cp_r(os.path.join(networkd_ci_temp_dir, unit + '.d'), os.path.join(network_unit_dir, unit + '.d'))

        if unit.endswith('.conf'):
            dropin = unit
            unit = os.path.dirname(dropin).rstrip('.d')
            dropindir = os.path.join(network_unit_dir, unit + '.d')
            mkdir_p(dropindir)
            cp(os.path.join(networkd_ci_temp_dir, dropin), dropindir)

        cp(os.path.join(networkd_ci_temp_dir, unit), network_unit_dir)

        if unit.endswith('.link'):
            has_link = True

    if has_link:
        udev_reload()

def remove_network_unit(*units):
    """
    Remove previously copied unit files from the testbed.

    Drop-ins will be removed automatically.
    """
    has_link = False
    for unit in units:
        rm_f(os.path.join(network_unit_dir, unit))
        rm_rf(os.path.join(network_unit_dir, unit + '.d'))

        if unit.endswith('.link') or unit.endswith('.link.d'):
            has_link = True

    if has_link:
        udev_reload()

def clear_network_units():
    has_link = False
    if os.path.exists(network_unit_dir):
        units = os.listdir(network_unit_dir)
        for unit in units:
            if unit.endswith('.link') or unit.endswith('.link.d'):
                has_link = True

    rm_rf(network_unit_dir)

    if has_link:
        udev_reload()

def copy_networkd_conf_dropin(*dropins):
    """Copy networkd.conf dropin files into the testbed."""
    mkdir_p(networkd_conf_dropin_dir)
    for dropin in dropins:
        cp(os.path.join(networkd_ci_temp_dir, dropin), networkd_conf_dropin_dir)

def remove_networkd_conf_dropin(*dropins):
    """Remove previously copied networkd.conf dropin files from the testbed."""
    for dropin in dropins:
        rm_f(os.path.join(networkd_conf_dropin_dir, dropin))

def clear_networkd_conf_dropins():
    rm_rf(networkd_conf_dropin_dir)

def copy_udev_rule(*rules):
    """Copy udev rules"""
    mkdir_p(udev_rules_dir)
    for rule in rules:
        cp(os.path.join(networkd_ci_temp_dir, rule), udev_rules_dir)

def remove_udev_rule(*rules):
    """Remove previously copied udev rules"""
    for rule in rules:
        rm_f(os.path.join(udev_rules_dir, rule))

def clear_udev_rules():
    rm_rf(udev_rules_dir)

def save_active_units():
    for u in ['systemd-networkd.socket', 'systemd-networkd.service',
              'systemd-resolved.service', 'systemd-timesyncd.service',
              'firewalld.service']:
        if call(f'systemctl is-active --quiet {u}') == 0:
            call(f'systemctl stop {u}')
            active_units.append(u)

def restore_active_units():
    if 'systemd-networkd.socket' in active_units:
        call('systemctl stop systemd-networkd.socket systemd-networkd.service')
    for u in active_units:
        call(f'systemctl restart {u}')

def create_unit_dropin(unit, contents):
    mkdir_p(f'/run/systemd/system/{unit}.d')
    with open(f'/run/systemd/system/{unit}.d/00-override.conf', mode='w', encoding='utf-8') as f:
        f.write('\n'.join(contents))

def create_service_dropin(service, command, reload_command=None, additional_settings=None):
    drop_in = [
        '[Service]',
        'ExecStart=',
        f'ExecStart=!!{valgrind_cmd}{command}',
    ]
    if reload_command:
        drop_in += [
            'ExecReload=',
            f'ExecReload={valgrind_cmd}{reload_command}',
        ]
    if enable_debug:
        drop_in += ['Environment=SYSTEMD_LOG_LEVEL=debug']
    if asan_options:
        drop_in += [f'Environment=ASAN_OPTIONS="{asan_options}"']
    if lsan_options:
        drop_in += [f'Environment=LSAN_OPTIONS="{lsan_options}"']
    if ubsan_options:
        drop_in += [f'Environment=UBSAN_OPTIONS="{ubsan_options}"']
    if asan_options or lsan_options or ubsan_options:
        drop_in += ['SystemCallFilter=']
    if use_valgrind or asan_options or lsan_options or ubsan_options:
        drop_in += ['MemoryDenyWriteExecute=no']
    if use_valgrind:
        drop_in += [
            'Environment=SYSTEMD_MEMPOOL=0',
            'PrivateTmp=yes',
        ]
    if with_coverage:
        drop_in += [
            'ProtectSystem=no',
            'ProtectHome=no',
        ]
    if additional_settings:
        drop_in += additional_settings

    create_unit_dropin(f'{service}.service', drop_in)

def link_exists(link):
    return call_quiet(f'ip link show {link}') == 0

def link_resolve(link):
    return check_output(f'ip link show {link}').split(':')[1].strip()

def remove_link(*links, protect=False):
    for link in links:
        if protect and link in protected_links:
            continue
        if link_exists(link):
            call(f'ip link del dev {link}')

def save_existing_links():
    links = os.listdir('/sys/class/net')
    for link in links:
        if link_exists(link):
            protected_links.add(link)

    print('### The following links will be protected:')
    print(', '.join(sorted(list(protected_links))))

def flush_links():
    links = os.listdir('/sys/class/net')
    remove_link(*links, protect=True)

def flush_nexthops():
    # Currently, the 'ip nexthop' command does not have 'save' and 'restore'.
    # Hence, we cannot restore nexthops in a simple way.
    # Let's assume there is no nexthop used in the system
    call_quiet('ip nexthop flush')

def save_routes():
    # pylint: disable=global-statement
    global saved_routes
    saved_routes = check_output('ip route show table all')
    print('### The following routes will be protected:')
    print(saved_routes)

def flush_routes():
    have = False
    output = check_output('ip route show table all')
    for line in output.splitlines():
        if line in saved_routes:
            continue
        if 'proto kernel' in line:
            continue
        if ' dev ' in line and not ' dev lo ' in line:
            continue
        if not have:
            have = True
            print('### Removing routes that did not exist when the test started.')
        print(f'# {line}')
        call(f'ip route del {line}')

def save_routing_policy_rules():
    # pylint: disable=global-statement
    global saved_ipv4_rules, saved_ipv6_rules
    def save(ipv):
        output = check_output(f'ip -{ipv} rule show')
        print(f'### The following IPv{ipv} routing policy rules will be protected:')
        print(output)
        return output

    saved_ipv4_rules = save(4)
    saved_ipv6_rules = save(6)

def flush_routing_policy_rules():
    def flush(ipv, saved_rules):
        have = False
        output = check_output(f'ip -{ipv} rule show')
        for line in output.splitlines():
            if line in saved_rules:
                continue
            if not have:
                have = True
                print(f'### Removing IPv{ipv} routing policy rules that did not exist when the test started.')
            print(f'# {line}')
            words = line.replace('lookup [l3mdev-table]', 'l3mdev').split()
            priority = words[0].rstrip(':')
            call(f'ip -{ipv} rule del priority {priority} ' + ' '.join(words[1:]))

    flush(4, saved_ipv4_rules)
    flush(6, saved_ipv6_rules)

def flush_fou_ports():
    ret = run('ip fou show')
    if ret.returncode != 0:
        return # fou may not be supported
    for line in ret.stdout.splitlines():
        port = line.split()[1]
        call(f'ip fou del port {port}')

def flush_l2tp_tunnels():
    tids = []
    ret = run('ip l2tp show tunnel')
    if ret.returncode != 0:
        return # l2tp may not be supported
    for line in ret.stdout.splitlines():
        words = line.split()
        if words[0] == 'Tunnel':
            tid = words[1].rstrip(',')
            call(f'ip l2tp del tunnel tunnel_id {tid}')
            tids.append(tid)

    # Removing L2TP tunnel is asynchronous and slightly takes a time.
    for tid in tids:
        for _ in range(50):
            r = run(f'ip l2tp show tunnel tunnel_id {tid}')
            if r.returncode != 0 or len(r.stdout.rstrip()) == 0:
                break
            time.sleep(.2)
        else:
            print(f'Cannot remove L2TP tunnel {tid}, ignoring.')

def save_timezone():
    # pylint: disable=global-statement
    global saved_timezone
    r = run(*timedatectl_cmd, 'show', '--value', '--property', 'Timezone', env=env)
    if r.returncode == 0:
        saved_timezone = r.stdout.rstrip()
        print(f'### Saved timezone: {saved_timezone}')

def restore_timezone():
    if saved_timezone:
        call(*timedatectl_cmd, 'set-timezone', f'{saved_timezone}', env=env)

def read_link_attr(*args):
    with open(os.path.join('/sys/class/net', *args), encoding='utf-8') as f:
        return f.readline().strip()

def read_link_state_file(link):
    ifindex = read_link_attr(link, 'ifindex')
    path = os.path.join('/run/systemd/netif/links', ifindex)
    with open(path, encoding='utf-8') as f:
        return f.read()

def read_ip_sysctl_attr(link, attribute, ipv):
    with open(os.path.join('/proc/sys/net', ipv, 'conf', link, attribute), encoding='utf-8') as f:
        return f.readline().strip()

def read_ipv6_sysctl_attr(link, attribute):
    return read_ip_sysctl_attr(link, attribute, 'ipv6')

def read_ipv4_sysctl_attr(link, attribute):
    return read_ip_sysctl_attr(link, attribute, 'ipv4')

def start_dnsmasq(*additional_options, interface='veth-peer', lease_time='2m', ipv4_range='192.168.5.10,192.168.5.200', ipv4_router='192.168.5.1', ipv6_range='2600::10,2600::20'):
    command = (
        'dnsmasq',
        f'--log-facility={dnsmasq_log_file}',
        '--log-queries=extra',
        '--log-dhcp',
        f'--pid-file={dnsmasq_pid_file}',
        '--conf-file=/dev/null',
        '--bind-interfaces',
        f'--interface={interface}',
        f'--dhcp-leasefile={dnsmasq_lease_file}',
        '--enable-ra',
        f'--dhcp-range={ipv6_range},{lease_time}',
        f'--dhcp-range={ipv4_range},{lease_time}',
        '--dhcp-option=option:mtu,1492',
        f'--dhcp-option=option:router,{ipv4_router}',
        '--port=0',
        '--no-resolv',
    ) + additional_options
    check_output(*command)

def stop_by_pid_file(pid_file):
    if not os.path.exists(pid_file):
        return
    with open(pid_file, 'r', encoding='utf-8') as f:
        pid = f.read().rstrip(' \t\r\n\0')
        os.kill(int(pid), signal.SIGTERM)
        for _ in range(25):
            try:
                os.kill(int(pid), 0)
                print(f"PID {pid} is still alive, waiting...")
                time.sleep(.2)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    break
                print(f"Unexpected exception when waiting for {pid} to die: {e.errno}")
    os.remove(pid_file)

def stop_dnsmasq():
    stop_by_pid_file(dnsmasq_pid_file)
    rm_f(dnsmasq_lease_file)
    rm_f(dnsmasq_log_file)

def read_dnsmasq_log_file():
    with open(dnsmasq_log_file, encoding='utf-8') as f:
        return f.read()

def start_isc_dhcpd(conf_file, ipv, interface='veth-peer'):
    conf_file_path = os.path.join(networkd_ci_temp_dir, conf_file)
    isc_dhcpd_command = f'dhcpd {ipv} -cf {conf_file_path} -lf {isc_dhcpd_lease_file} -pf {isc_dhcpd_pid_file} {interface}'
    touch(isc_dhcpd_lease_file)
    check_output(isc_dhcpd_command)

def stop_isc_dhcpd():
    stop_by_pid_file(isc_dhcpd_pid_file)
    rm_f(isc_dhcpd_lease_file)

def networkd_invocation_id():
    return check_output('systemctl show --value -p InvocationID systemd-networkd.service')

def read_networkd_log(invocation_id=None):
    if not invocation_id:
        invocation_id = networkd_invocation_id()
    return check_output('journalctl _SYSTEMD_INVOCATION_ID=' + invocation_id)

def stop_networkd(show_logs=True):
    if show_logs:
        invocation_id = networkd_invocation_id()
    check_output('systemctl stop systemd-networkd.socket')
    check_output('systemctl stop systemd-networkd.service')
    if show_logs:
        print(read_networkd_log(invocation_id))

def start_networkd():
    check_output('systemctl start systemd-networkd')

def restart_networkd(show_logs=True):
    if show_logs:
        invocation_id = networkd_invocation_id()
    check_output('systemctl restart systemd-networkd.service')
    if show_logs:
        print(read_networkd_log(invocation_id))

def networkd_pid():
    return int(check_output('systemctl show --value -p MainPID systemd-networkd.service'))

def networkctl_reconfigure(*links):
    check_output(*networkctl_cmd, 'reconfigure', *links, env=env)

def networkctl_reload(sleep_time=1):
    check_output(*networkctl_cmd, 'reload', env=env)
    # 'networkctl reload' asynchronously reconfigure links.
    # Hence, we need to wait for a short time for link to be in configuring state.
    if sleep_time > 0:
        time.sleep(sleep_time)

def setup_common():
    print()

def tear_down_common():
    # 1. stop DHCP servers
    stop_dnsmasq()
    stop_isc_dhcpd()

    # 2. remove modules
    call_quiet('rmmod netdevsim')
    call_quiet('rmmod sch_teql')

    # 3. remove network namespace
    call_quiet('ip netns del ns99')

    # 4. remove links
    flush_l2tp_tunnels()
    flush_links()

    # 5. stop networkd
    stop_networkd()

    # 6. remove configs
    clear_network_units()
    clear_networkd_conf_dropins()

    # 7. flush settings
    flush_fou_ports()
    flush_nexthops()
    flush_routing_policy_rules()
    flush_routes()

class Utilities():
    # pylint: disable=no-member

    def check_link_exists(self, link, expected=True):
        if expected:
            self.assertTrue(link_exists(link))
        else:
            self.assertFalse(link_exists(link))

    def check_link_attr(self, *args):
        self.assertEqual(read_link_attr(*args[:-1]), args[-1])

    def check_bridge_port_attr(self, master, port, attribute, expected, allow_enoent=False):
        path = os.path.join('/sys/devices/virtual/net', master, 'lower_' + port, 'brport', attribute)
        if allow_enoent and not os.path.exists(path):
            return
        with open(path, encoding='utf-8') as f:
            self.assertEqual(f.readline().strip(), expected)

    def check_ipv4_sysctl_attr(self, link, attribute, expected):
        self.assertEqual(read_ipv4_sysctl_attr(link, attribute), expected)

    def check_ipv6_sysctl_attr(self, link, attribute, expected):
        self.assertEqual(read_ipv6_sysctl_attr(link, attribute), expected)

    def wait_links(self, *links, timeout=20, fail_assert=True):
        def links_exist(*links):
            for link in links:
                if not link_exists(link):
                    return False
            return True

        for iteration in range(timeout + 1):
            if iteration > 0:
                time.sleep(1)

            if links_exist(*links):
                return True
        if fail_assert:
            self.fail('Timed out waiting for all links to be created: ' + ', '.join(list(links)))
        return False

    def wait_activated(self, link, state='down', timeout=20, fail_assert=True):
        # wait for the interface is activated.
        invocation_id = check_output('systemctl show systemd-networkd -p InvocationID --value')
        needle = f'{link}: Bringing link {state}'
        flag = state.upper()
        for iteration in range(timeout + 1):
            if iteration != 0:
                time.sleep(1)
            if not link_exists(link):
                continue
            output = check_output('journalctl _SYSTEMD_INVOCATION_ID=' + invocation_id)
            if needle in output and flag in check_output(f'ip link show {link}'):
                return True
        if fail_assert:
            self.fail(f'Timed out waiting for {link} activated.')
        return False

    def wait_operstate(self, link, operstate='degraded', setup_state='configured', setup_timeout=5, fail_assert=True):
        """Wait for the link to reach the specified operstate and/or setup state.

        Specify None or '' for either operstate or setup_state to ignore that state.
        This will recheck until the state conditions are met or the timeout expires.

        If the link successfully matches the requested state, this returns True.
        If this times out waiting for the link to match, the behavior depends on the
        'fail_assert' parameter; if True, this causes a test assertion failure,
        otherwise this returns False.  The default is to cause assertion failure.

        Note that this function matches on *exactly* the given operstate and setup_state.
        To wait for a link to reach *or exceed* a given operstate, use wait_online().
        """
        if not operstate:
            operstate = r'\S+'
        if not setup_state:
            setup_state = r'\S+'

        for secs in range(setup_timeout + 1):
            if secs != 0:
                time.sleep(1)
            if not link_exists(link):
                continue
            output = check_output(*networkctl_cmd, '-n', '0', 'status', link, env=env)
            if re.search(rf'(?m)^\s*State:\s+{operstate}\s+\({setup_state}\)\s*$', output):
                return True

        if fail_assert:
            self.fail(f'Timed out waiting for {link} to reach state {operstate}/{setup_state}')
        return False

    def wait_online(self, links_with_operstate, timeout='20s', bool_any=False, ipv4=False, ipv6=False, setup_state='configured', setup_timeout=5):
        """Wait for the links to reach the specified operstate and/or setup state.

        This is similar to wait_operstate() but can be used for multiple links,
        and it also calls systemd-networkd-wait-online to wait for the given operstate.
        The operstate should be specified in the link name, like 'eth0:degraded'.
        If just a link name is provided, wait-online's default operstate to wait for is degraded.

        The 'timeout' parameter controls the systemd-networkd-wait-online timeout, and the
        'setup_timeout' controls the per-link timeout waiting for the setup_state.

        Set 'bool_any' to True to wait for any (instead of all) of the given links.
        If this is set, no setup_state checks are done.

        Set 'ipv4' or 'ipv6' to True to wait for IPv4 address or IPv6 address, respectively, of each of the given links.
        This is applied only for the operational state 'degraded' or above.

        Note that this function waits for the links to reach *or exceed* the given operstate.
        However, the setup_state, if specified, must be matched *exactly*.

        This returns if the links reached the requested operstate/setup_state; otherwise it
        raises CalledProcessError or fails test assertion.
        """
        args = wait_online_cmd + [f'--timeout={timeout}'] + [f'--interface={link}' for link in links_with_operstate] + [f'--ignore={link}' for link in protected_links]
        if bool_any:
            args += ['--any']
        if ipv4:
            args += ['--ipv4']
        if ipv6:
            args += ['--ipv6']
        try:
            check_output(*args, env=wait_online_env)
        except subprocess.CalledProcessError:
            # show detailed status on failure
            for link in links_with_operstate:
                name = link.split(':')[0]
                if link_exists(name):
                    call(*networkctl_cmd, '-n', '0', 'status', name, env=env)
            raise
        if not bool_any and setup_state:
            for link in links_with_operstate:
                self.wait_operstate(link.split(':')[0], None, setup_state, setup_timeout)

    def wait_address(self, link, address_regex, scope='global', ipv='', timeout_sec=100):
        for i in range(timeout_sec):
            if i > 0:
                time.sleep(1)
            output = check_output(f'ip {ipv} address show dev {link} scope {scope}')
            if re.search(address_regex, output) and 'tentative' not in output:
                break

        self.assertRegex(output, address_regex)

    def wait_address_dropped(self, link, address_regex, scope='global', ipv='', timeout_sec=100):
        for i in range(timeout_sec):
            if i > 0:
                time.sleep(1)
            output = check_output(f'ip {ipv} address show dev {link} scope {scope}')
            if not re.search(address_regex, output):
                break

        self.assertNotRegex(output, address_regex)

    def wait_route(self, link, route_regex, table='main', ipv='', timeout_sec=100):
        for i in range(timeout_sec):
            if i > 0:
                time.sleep(1)
            output = check_output(f'ip {ipv} route show dev {link} table {table}')
            if re.search(route_regex, output):
                break

        self.assertRegex(output, route_regex)

    def check_netlabel(self, interface, address, label='system_u:object_r:root_t:s0'):
        if not shutil.which('selinuxenabled'):
            print('## Checking NetLabel skipped: selinuxenabled command not found.')
        elif call_quiet('selinuxenabled') != 0:
            print('## Checking NetLabel skipped: SELinux disabled.')
        elif not shutil.which('netlabelctl'): # not packaged by all distros
            print('## Checking NetLabel skipped: netlabelctl command not found.')
        else:
            output = check_output('netlabelctl unlbl list')
            print(output)
            self.assertRegex(output, f'interface:{interface},address:{address},label:"{label}"')

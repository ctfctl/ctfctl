from os import environ
from os import chdir
from os import walk
from os import stat

from os.path import join
from os.path import basename
from os.path import sep
from os.path import dirname
from os.path import normpath
from os.path import isdir
from os.path import isfile

from sys import exit

from re import match
from re import findall

from base64 import b64encode

from socket import timeout

from stat import S_ISDIR

from signal import SIGWINCH
from signal import signal

from time import sleep
from time import time

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

from pexpect import spawn

from digitalocean import Domain
from digitalocean import Droplet
from digitalocean import Manager
from digitalocean import SSHKey
from digitalocean import Record

from paramiko import SSHClient
from paramiko import AutoAddPolicy

from config import basedir
from config import ctf_domain
from config import ssh_username
from config import ssh_port
from config import ssh_timeout
from config import vm_bootstrap_timeout
from config import vm_default_packages

from util import transfer_status
from util import droplet_action_wait
from util import print_status_cycle
from util import get_expose_port
from util import get_systemd_timer_service

from shell import sigwinch_passthrough
from shell import query_yes_no
from shell import red
from shell import green
from shell import yellow
from shell import bright


if 'TOKEN' not in environ:
    print('ERROR: missing env var TOKEN (digital ocean access token)')
    exit(1)


TOKEN = environ['TOKEN']
COMMANDS = []

manager = Manager(token=TOKEN)


def command(func):
    COMMANDS.append(func.__name__)
    return func


def help():
    print("Available commands:")
    for name in sorted(COMMANDS):
        print(f'- {name}')



@command
def add_pub_key(path, name):
    with open(path) as f:
        user_ssh_key = f.read()

    key = SSHKey(token=TOKEN,
                 name=name,
                 public_key=user_ssh_key)
    key.create()
    print(f'[+] added ssh-key: {name}')


@command
def sync_pub_keys():
    """Synchronize all existing public keys to all VM's
       Requires that the current users key already works.

       Use add_pub_key(path, name) to add a new one.
    """
    keys = '\n'.join([k.public_key for k in manager.get_all_sshkeys()]) + '\n'
    keys = b64encode(keys.encode()).decode()
    assert keys
    for vm in get():
        if 'active' != vm.status:
            continue
        print(f'-> sync keys to {vm.name}...')
        # TODO add sanaty checks and overwrite
        ssh(vm, f'echo {keys}|base64 -d >> /root/.ssh/authorized_keys')


@command
def create(name, cpu=1, ram=1, wait=True, bootstrap_vm=True):
    """Create a new vm and return its Droplet object.

    params:
    - name: string name of the vm

    optional:
    - cpu: int number of CPUs (default: 1)
    - ram: int amount of RAM in gigabyte (default: 1)
    - wait: bool whether to wait for completion
    - bootstrap_vm: bool whether to bootstrap the node

    return:
      Droplet object of the new VM
    """
    label = f'Creating vm {name} (takes several minutes)...'
    print(f'[+] {label}', end='', flush=True)

    keys = manager.get_all_sshkeys()
    droplet = Droplet(
        token=TOKEN,
        name=name,
        region='fra1',
        image='debian-9-x64',
        distro='debian',
        size_slug=f's-{cpu}vcpu-{ram}gb',
        ssh_keys=keys,
        backups=False)
    droplet.create()

    # handle create action
    actions = droplet.get_actions()
    create_action = list(filter(lambda action: action.type == 'create',
                                actions))[0]
    if wait:
        try:
            droplet_action_wait(create_action,
                                callback=print_status_cycle(labal=label),
                                timeout=vm_bootstrap_timeout)
        except timeout as e:
            print(f'\n[-] Failed, retrying: {e}')
            return create(name, cpu, ram, wait, bootstrap_vm)

    # print droplet infos
    droplet.load()
    print('done')
    print(f'{name}: {create_action.status} -> {droplet.ip_address}')

    if bootstrap_vm:
        uname = ''
        status = print_status_cycle('Booting (takes several minutes)...')
        while 'Linux' not in uname:
            status()
            try:
                uname, stderr = ssh(droplet, 'uname -s', timeout=2,
                                    print_streams=False, print_errors=False)
            except Exception:
                # TODO: ignores Permission denied (publickey)
                pass
            sleep(0.20)
        success = bootstrap(droplet)
        if not success:
            destroy(droplet, ask=False)
            droplet = create(name, cpu, ram, wait, bootstrap_vm)

    return droplet


@command
def create_challenge(challenge_path, cpu=1, ram=1, run=True):
    """Create a new bootstrapped vm with a deployed challenge and return
    its Droplet object.

    params:
    - challenge_path: string path of the challenge

    optional:
    - cpu: int number of CPUs (default: 1)
    - ram: int amount of RAM in gigabyte (default: 1)
    - run: bool wether to run the challenge container (default: True)

    return:
      Droplet object of the new VM
    """
    if challenge_path.endswith('/'):
        challenge_path = challenge_path[:-1]
    challenge_name = basename(challenge_path)
    vms = get(challenge_name)
    if vms:
        names = [vm.name for vm in vms]
        counter = max(map(int, [name[len(name) - name[::-1].index('-')]
                                if match('.+\\-[0-9]+', name) else '0'
                                for name in names]))

        challenge_name = f'{challenge_name}-{counter + 1}'
        print(f'[*] Challenge already exists as: {", ".join(names)}')
        confirm = query_yes_no(f'Create another one as {challenge_name}?')
        if not confirm:
            return

    vm = create(challenge_name, cpu, ram)
    if vm:
        challenge(vm, challenge_path, run=run)


@command
def bootstrap(name, wait=True):
    # TODO: API should only work for a single vm
    for droplet in get(name):
        with SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(AutoAddPolicy)

            try:
                client.connect(droplet.ip_address,
                               port=ssh_port,
                               username=ssh_username,
                               timeout=ssh_timeout)

                # Update system
                stdin, stdout, stderr = client.exec_command(f'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y')
                for line in stdout:
                    print(line, end='', flush=True)
                print(stderr.read().decode())

                # download install script
                stdin, stdout, stderr = client.exec_command(f'wget https://raw.githubusercontent.com/gh2o/digitalocean-debian-to-arch/debian9/install.sh -O install.sh')
                for line in stdout:
                    print(line, end='', flush=True)
                print(stderr.read().decode())

                # install Arch Linux
                options = f'--kernel_package=linux-hardened --grub_timeout=1 --extra_packages="{" ".join(vm_default_packages)}"'
                stdin, stdout, stderr = client.exec_command(f'bash install.sh {options}')
                stdin.write('wipe this droplet\n')
                for line in stdout:
                    print(line, end='', flush=True)
                print(stderr.read().decode())
            except timeout:
                print(f'ssh: connect to host {droplet.ip_address} port 22: timed out')
                continue
            except Exception as e:
                print(str(e))

        if wait:
            start = time()
            uname = ''
            status = print_status_cycle('Booting (takes several minutes)...')
            while '-hardened' not in uname:
                status()
                try:
                    uname, stderr = ssh(droplet, 'uname -r', timeout=2,
                                        print_streams=False, print_errors=False)
                    stdout, stderr = ssh(droplet, 'systemctl enable --now docker')
                except Exception:
                    pass
                sleep(0.20)

                if time() > start + vm_bootstrap_timeout:
                    print('\n[-] Failed to spawn in time, retrying...')
                    return False

        print(f'{name}: -> {droplet.ip_address}')
        return True


def challenge(vm, challenge_path, run=True):
    """Upload, build and optionally run a challenge on a VM

    params:
    - vm: string name, regex or Droplet objects
    - challenge_path: string path of the challenge
    - start: bool wether to run the challenge container
    """
    expose = get_expose_port(challenge_path)

    for droplet in get(vm):
        copy_to(vm, challenge_path, '/root/ctf')
        commands = ['docker build -t ctf ctf']
        if run:
            commands.append('docker stop ctf')
            commands.append('docker rm ctf')
            commands.append(
                f'docker run -d --restart always '
                f'-p {expose}:{expose} --name ctf -it ctf')
        ssh(vm, commands)
        print(f'started challenge -> {droplet.ip_address} {expose}')

def create_systemd_monitoring_timer(vm):
        timer = f"""[Unit]
Description=Monitoring %I

[Timer]
OnBootSec=1s
OnUnitActiveSec=5m
RuntimeMaxSec=240

[Install]
WantedBy=timers.target
"""

        service = f"""[Unit]
Description=Monitoring %I

[Service]
ExecStart=/root/ctf/%i/monitoring.sh
"""

        ssh(vm, [f"echo '{timer}' > /etc/systemd/system/monitoring@.timer",
                 f"echo '{service}' > /etc/systemd/system/monitoring@.service"])


def get_monitorable_challs():
    result = []
    num_sep = ".".count(sep)
    for root, dirs, files in walk(".", topdown=False):
        num_sep_this = root.count(sep)

        if num_sep + 2 != num_sep_this:
            continue

        for dname in dirs:
            if dname == "exploit":
                result.append(root)
    return result


@command
def create_monitoring_for_challenge(challenge_path, vm="monitoring"):
    monitorable_challs = [basename(a) for a in get_monitorable_challs()]
    if challenge_path.endswith('/'):
        challenge_path = challenge_path[:-1]
    challenge_name = basename(challenge_path)

    print(f"[+] generating monitoring for {challenge_name}")

    if not get(vm) or get(vm)[0].status != "active":
        print(f"Could not find active monitoring vm {vm}.")
        return

    if challenge_name not in monitorable_challs:
        print(f"Could not find exploit directory for {challenge_path}.")
        return

    source_dir = challenge_path + "/exploit"
    challenge_vm = get(challenge_name)
    if not challenge_vm:
        print(f"ERROR: Could not find vm with name {challenge_name}")
        return

    copy_to(vm, source_dir, challenge_name)

    ip = challenge_vm[0].ip_address
    port = get_expose_port(challenge_path)
    target_path = "/root/ctf/" + challenge_name

    monitoring_script_path = f"{target_path}/monitoring.sh"
    image_name = challenge_name
    commands = [
            f"echo '#!/bin/sh' > {monitoring_script_path}",
            f"echo '(sleep 120; docker kill {image_name}) & docker run --rm -e 'IP={ip}' -e 'PORT={port}' --name {image_name} {image_name}' >> {monitoring_script_path}",
            f"chmod +x {monitoring_script_path}",
            f"docker build {target_path}/. -t {image_name}",
            f"systemctl enable --now monitoring@{challenge_name}.timer"]
    ssh(vm, commands)
    print("[+] done")


@command
def create_monitoring(name="monitoring"):
    """ Creates a vm which will monitor all challenges containing a folder
    'exploit' with a Dockerfile in it, i.e. we expect a folder structure like:
    ./<category>/<challenge_name>/exploit/Dockerfile

    optional:
    - name: name of the monitoring
    """

    if not get(name):
        print(f"could not find vm with name {name}. Will create one.")
        create(name)
        create_systemd_monitoring_timer(name)

    monitorable_challs = get_monitorable_challs()
    print(f"creating monitoring for {monitorable_challs}")

    for challenge_path in monitorable_challs:
        create_monitoring_for_challenge(challenge_path, name)


def verify_monitor_status(challenge_name):
    ssh("monitoring", f"bash /root/ctf/{challenge_name}/monitoring.sh")


def get_vm_status(vm):
    commands = ["top -bn1 | grep \"Cpu\" | awk -F \",\"  '{ split($4, subfield, \" \"); print 100 - subfield[1]}'",
            "free -m | awk '/Mem:/ { print $3 \" \" $2}'",
            "df -h | awk '/\/$/ {print $(NF-3) \" \" $(NF-2) \" \" $(NF-1)}'" ]

    vm = get(vm)
    output, _ = ssh(vm, commands, print_streams=False, stdout_as_list=True)
    if not output:
        return None
    else:
        cpu_percent = output[0].rstrip()
        mem_cur, mem_total = output[1].rstrip().split(" ")
        disk_cur, disk_total, disk_percent = output[2].rstrip().split(" ")

        return {"cpu": cpu_percent,
                "mem": (mem_cur, mem_total),
                "disk": (disk_cur, disk_total, disk_percent)}


@command
def health_status(vm=None, show_pwn=True, show_system=True, monitoring_name='monitoring'):
    """Checks the health status of all challenges with a pwn script,
    i.e. having  a folder structure like: ./<category>/<challenge_name>/exploit/Dockerfile

    optional:
    - vm: string name, regex or Droplet objects, None shows all VM's (default: None)
    - show_pwn: bool show pwn script status (default: True)
    - show_system: bool show pwn script status (default: True)
    - monitoring_name: string the name of the monitoring vm (default: monitoring)
    """
    monitoring_vm = get(monitoring_name)

    if not monitoring_vm or monitoring_vm[0].status != "active":
        print(red(f"could not find running vm with name {monitoring_name}. Exiting now."))
        return

    def show_system_status(vm):
        vm = get(vm)
        if not vm or vm[0].status != "active":
            print(red("\tCould not find running VM!"))
        else:
            status = get_vm_status(vm)
            cpu, mem, disk = status["cpu"], status["mem"], status["disk"]
            print(bright("\tCPU: ") + f"{cpu}%")
            print(bright("\tMem: ") + f"{mem[0]}MiB/{mem[1]}MiB {100 * int(mem[0]) // int(mem[1])}%")
            print(bright("\tDisk: ") + f"{disk[0]}/{disk[1]}  {disk[2]}")

    vms = [vm.name for vm in get(vm)] if vm else list(map(basename, get_monitorable_challs()))

    for challenge_name in vms:
        print(f"[*] monitoring report for {challenge_name}:")

        if show_pwn:
            output, _ = ssh(monitoring_vm, f"systemctl status monitoring@{challenge_name}", print_streams=False)

            status_line = findall(r"Main PID: .*", output)
            last_update = findall(r"; .* ago",output)
            print("\tpwn status: ", end='')
            if not status_line:
                print(red("ERROR. Could not find expected timer output."))
            else:
                last_update = last_update[0]
                if "status" in status_line[0]:
                    if "0/SUCCESS" in status_line[0]:
                        print(green("OK. ") + bright(last_update))
                    else:
                        print(red("ERROR! Pwn script panicked. ") + bright(last_update))
                else:
                    print(yellow("pwn script currently running... ") + bright(last_update))

        if show_system:
            show_system_status(challenge_name)

    if not vm and show_system:
        print(f"[*] monitoring report for ctfd:")
        show_system_status('ctfd')
        print(f"[*] monitoring report for ctfd-backup:")
        show_system_status('ctfd-backup')


@command
def create_backup(from_vm_name, to_vm_name="backup"):
    """Creates a backup droplet if needed and syncs the data from the
    vm {from_vm_name} to the backup every 10 minutes"""

    if not get(from_vm_name):
        print(f"could not find to-be-backuped vm {from_vm_name}!")
        return

    if not get(to_vm_name):
        print(f"could not find backup server for vm {to_vm_name}. Will create one.")
        create(to_vm_name)

    ip_addr = get(from_vm_name)[0].ip_address

    # generate keys for backup server
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048)

    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption()).decode('utf8')
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH).decode('utf8')

    ssh(from_vm_name, f"echo '{public_key}' >> /root/.ssh/authorized_keys")

    backup_script_path = f"/root/backup_{from_vm_name}.sh"

    systemd_configs = get_systemd_timer_service(
            f"Backup-{from_vm_name}",
            f"{backup_script_path}"
            )

    timer = systemd_configs["timer"]
    service = systemd_configs["service"]

    commands = [f"echo '{private_key}' > /root/.ssh/id_{from_vm_name}_rsa",
                f"chmod 0600 /root/.ssh/id_{from_vm_name}_rsa",
                "pacman --noconfirm --needed -Syu borg socat",

                # init the borg repo
                "mkdir -p /root/backups",
                "borg init -e none /root/backups",

                # listening to connections
                f"echo '#!/bin/sh' > {backup_script_path}",
                f"echo 'socat TCP-LISTEN:12345,fork \"EXEC:borg serve --append-only --restrict-to-path /root/backups/ --umask 077\"&' >> {backup_script_path}",
                # performing push from remote
                f"echo 'ssh -i /root/.ssh/id_{from_vm_name}_rsa -oStrictHostKeyChecking=no -R 12345:localhost:12345 {ip_addr} BORG_RSH=\"/root/socat-wrap.sh\" BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=yes borg create --stats ssh://foo/root/backups::{from_vm_name}-$(date +%Y-%m-%d-%R) /root/' >> {backup_script_path}",

                f"chmod +x {backup_script_path}",

                f"echo '{timer}' > /etc/systemd/system/backup_{from_vm_name}.timer",
                f"echo '{service}' > /etc/systemd/system/backup_{from_vm_name}.service",

                "systemctl daemon-reload",
                f"systemctl start backup_{from_vm_name}.timer",
                f"systemctl enable --now backup_{from_vm_name}.timer"]
    ssh(to_vm_name, commands)

    print(f'[*] created backup job for vm {from_vm_name}')

@command
def provision_ctfd(name="ctfd", backup_name="ctfd-backup"):
    """Creates a ctfd vm and a backup vm which will dump all the ctfd data
    every 10 minutes.

    optional:
    - name: name of the ctfd vm
    - backup_name: name of the backup vm

    return:
      None
    """
    if not get(name):
        print(f"could not find vm with name {name}. Will create one.")
        create(name)
    else:
        if not query_yes_no(f'There already exists a {name} vm. Sure you want to re-provision it?'):
            return

    ssh(name, ["pacman --noconfirm --needed -Syu docker-compose git borg socat",
               "git clone https://github.com/CTFd/CTFd.git ./CTFd",
               # generate secret key
               '''python -c "import os; f=open('./CTFd/.ctfd_secret_key', 'ba+');f.write(os.urandom(64)); f.close()"'''])

    copy_to(name, "./ctfd-config/ctfd-docker-compose.yml", "/root/CTFd/docker-compose.yml")
    copy_to(name, "./ctfd-config/Caddyfile", "/root/CTFd/Caddyfile")

    ssh(name, ["chmod +x /root/CTFd/docker-entrypoint.sh",
               "docker-compose -f /root/CTFd/docker-compose.yml up -d",
               "echo '#!/bin/bash' > /root/socat-wrap.sh",
               "echo 'exec socat STDIO TCP-CONNECT:localhost:12345' >> /root/socat-wrap.sh",
               "chmod +x /root/socat-wrap.sh"])
    create_backup("ctfd")

    print(f"[*] Done.")

@command
def resize(vm, cpu=None, ram=None):
    """Resize the CPU and/or memory of matching vm's

    params:
    - vm: string name, regex or Droplet objects
    - cpu: int number of CPUs (optional if ram is defined)
    - ram: int amount of RAM in gigabyte (optional if cpu is defined)
    """
    if cpu is None and ram is None:
        print('error: need at least one value for cpu or ram')
        return

    for droplet in get(vm):
        old_slug = match('\\w-(\\d+)vcpu-(\\d+)gb', droplet.size_slug)
        old_cpu = old_slug.group(1)
        old_ram = old_slug.group(1)
        new_cpu = old_cpu if cpu is None else cpu
        new_ram = old_ram if ram is None else ram
        size_slug = f's-{new_cpu}vcpu-{new_ram}gb'

        print(f'resizing {droplet.name} to {size_slug}')
        droplet.resize(size_slug)


@command
def rename(vm, name):
    """Rename a matching vm

    params:
    - vm: string name, regex or Droplet objects
    - name: string new name of the vm
    """
    droplets = get(vm)

    if not droplets:
        print(f"error: no matching vm for {name}")
        return

    names = [d.name for d in droplets]
    if len(droplets) > 1:
        print(f'error: need exactly one vm, found {", ".join(names)}')
        return

    droplet = droplets[0]
    droplet.rename(name)


@command
def destroy(vm, wait=True, ask=True):
    """Destroy matching vm's (use with care!)

    params:
    - vm: string name, regex or Droplet objects
    """
    droplets = get(vm)
    if not droplets:
        return

    names = [d.name for d in droplets]
    if ask and not query_yes_no(f'Sure you want to destroy: {", ".join(names)}'):
        return

    list(map(lambda d: d.destroy(), droplets))

    if not wait:
        return

    for droplet in droplets:
        label = f'Destroying vm {droplet.name}...'
        print(f'[+] {label}', end='', flush=True)
        # handle destroy action
        actions = droplet.get_actions()
        destroy_action = list(filter(lambda action: action.type == 'destroy',
                                     actions))[0]
        droplet_action_wait(destroy_action,
                            callback=print_status_cycle(labal=label))


@command
def get(vm=None):
    """Get Droplet objects of matching vm's

    params:
    - vm: string name, regex or Droplet objects

    returns a list of Droplet objects
    """
    if isinstance(vm, Droplet):
        return [vm]

    if isinstance(vm, list) and all([isinstance(v, Droplet) for v in vm]):
        return vm

    droplets = manager.get_all_droplets()
    if not vm:
        return droplets
    return list(filter(lambda d: match(f'^{vm}$', d.name), list(droplets)))


@command
def ls(vm=None):
    """List details of matching vm's

    params:
    - vm: string name, regex or Droplet objects
    """
    fallback_ip = 'unassigned'

    droplets = sorted(get(vm), key=lambda d: d.name)
    name_length = max([len(d.name) for d in droplets]) + 1 if droplets else 1
    ip_length = max([len(d.ip_address or fallback_ip) for d in droplets]) + 2 if droplets else 2
    status_length = max([len(d.status) for d in droplets]) + 1 if droplets else 1
    header = 'name'.ljust(name_length) + \
             'ip'.rjust(ip_length // 2 + 2).ljust(ip_length) + ' ' + \
             'cpu '.rjust(4) + \
             'mem '.rjust(6) + \
             'hdd '.rjust(4) +\
             'status'.rjust(status_length)
    print('=' * len(header))
    print(header)
    print('=' * len(header))
    for droplet in droplets:
        ip = droplet.ip_address or fallback_ip
        print(f'{droplet.name:<{name_length}}'
              f'{ip:>{ip_length}} '
              f'{droplet.vcpus:>3} '
              f'{droplet.memory:>5} '
              f'{droplet.disk:>3} '
              f'{droplet.status:>{status_length}}')
    print('-' * len(header))


@command
def power_on(vm):
    """Power on all matching vm's

    params:
    - vm: string name, regex or Droplet objects
    """
    list(map(lambda d: d.power_on(), get(vm)))


@command
def power_off(vm):
    """Power off all matching vm's

    params:
    - vm: string name, regex or Droplet objects
    """
    list(map(lambda d: d.power_off(), get(vm)))


@command
def power_cycle(vm):
    """Power cycle all matching vm's

    params:
    - vm: string name, regex or Droplet objects
    """
    list(map(lambda d: d.power_cycle(), get(vm)))


@command
def shutdown(vm):
    """Shutdown all matching vm's

    params:
    - vm: string name, regex or Droplet objects
    """
    list(map(lambda d: d.shutdown(), get(vm)))


@command
def reboot(vm):
    """Reboot all matching vm's

    params:
    - vm: string name, regex or Droplet objects
    """
    list(map(lambda d: d.reboot(), get(vm)))


@command
def status(vm):
    """Print status entries on all matching vm's

    params:
    - vm: string name, regex or Droplet objects
    """
    for droplet in get(vm):
        print(f'{droplet.name}: {droplet.status}')
        actions = droplet.get_actions()
        max_type = max(max([len(action.type) for action in actions]) + 2, 12)
        for action in actions:
            print(f' - {action.completed_at or action.started_at} {action.type:>{max_type}}: {action.status}')
        print()


@command
def ssh(vm, command=None, print_streams=True, print_errors=True, timeout=ssh_timeout, stdout_as_list=False):
    """Execute passed shell commands or invoke an interactive shell on all
    matching vm's

    params:
    - vm: string name, regex or Droplet objects

    optional:
    - command: empty to pop interactive shell
               string to execute a single commands
               list of strings to execute multiple commands
    """
    stdout_all = ''
    stderr_all = ''
    stdouts = []
    for droplet in get(vm):

        if not command:
            child = spawn(f'ssh -p {ssh_port} {ssh_username}@{droplet.ip_address}',
                          encoding='utf-8', timeout=timeout)
            signal(SIGWINCH, sigwinch_passthrough(child))
            child.interact()
            continue

        with SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(AutoAddPolicy)

            try:
                client.connect(droplet.ip_address,
                               port=ssh_port,
                               username=ssh_username,
                               timeout=timeout)

                def exec(command):
                    stdin, stdout, stderr = client.exec_command(command)
                    stdout_all = ''
                    stderr_all = ''
                    for line in stdout:
                        if print_streams:
                            print(line, end='', flush=True)
                        stdout_all += line
                    for line in stderr:
                        if print_streams:
                            print(line, end='', flush=True)
                        stderr_all += line
                    return stdout_all, stderr_all

                if isinstance(command, str):
                    stdout, stderr = exec(command)
                    stdout_all += stdout
                    stderr_all += stderr
                    continue

                if isinstance(command, list):
                    stdouts, stderrs = list(zip(*map(exec, command)))
                    stdout = '\n'.join(stdouts)
                    stderr = '\n'.join(stderrs)
                    stdout_all += stdout
                    stderr_all += stderr
                    continue

                # channel = client.invoke_shell()
                # posix_socket_shell(channel)
            except timeout:
                if print_errors:
                    print(f'ssh: connect to host {droplet.ip_address} port 22: timed out')

    if not print_streams:
        return stdouts if stdout_as_list else stdout_all, stderr_all


@command
def copy_to(vm, copy_from, copy_to):
    """Copies a file or a directory to the target VM's

    The CWD on the local host is the root dir of the challenge repository
    The CWD on the target host is /root/ctf

    params:
    - vm: string name, regex or Droplet objects
    - copy_from: string a relative or absolute path (file or directory)
    - copy_to: string a relative or absolute path (file or directory)
    """

    ctf_working_dir = '/root/ctf'
    copy_from = normpath(copy_from)
    copy_to = normpath(copy_to)
    chdir(basedir)

    for droplet in get(vm):
        with SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(AutoAddPolicy)

            try:
                client.connect(droplet.ip_address,
                               port=ssh_port,
                               username=ssh_username,
                               timeout=ssh_timeout)

                with client.open_sftp() as sftp:
                    # ensure default ctf cwd exists and is set
                    if not basename(ctf_working_dir) in sftp.listdir(dirname(ctf_working_dir)):
                        sftp.mkdir(ctf_working_dir, 0o755)
                    sftp.chdir(ctf_working_dir)

                    if isdir(copy_from):
                        # ensure target directory exists
                        if not basename(copy_to) in sftp.listdir(dirname(copy_to)):
                            sftp.mkdir(copy_to, 0o755)

                        # recursive directory copy
                        for root, dirs, files in walk(copy_from, topdown=True):
                            for name in files:
                                f_from = join(root, name)
                                f_to = f_from.replace(copy_from, copy_to, 1)
                                sftp.put(f_from, f_to, callback=transfer_status(f_to))
                                sftp.chmod(f_to, stat(f_from).st_mode)
                                print()
                            for name in dirs:
                                d = join(root, name).replace(copy_from, copy_to, 1)
                                if not basename(d) in sftp.listdir(dirname(d)):
                                    sftp.mkdir(d, stat(copy_from).st_mode)

                    elif isfile(copy_from):
                        # check if target is an existing directory to copy into
                        if basename(copy_to) in sftp.listdir(dirname(copy_to)):
                            to_stat = sftp.stat(copy_to)
                            if S_ISDIR(to_stat.st_mode):
                                copy_to = join(copy_to, basename(copy_from))
                        sftp.put(copy_from, copy_to, callback=transfer_status(copy_to))
                        sftp.chmod(copy_to, stat(copy_from).st_mode)
                        print()

            except timeout:
                print(f'ssh: connect to host {droplet.ip_address} port 22: timed out')


@command
def update(vm, reboot=None):
    for droplet in get(vm):
        reboot_message = f'[*] Kernel of {droplet.name} upgraded, rebooting...'
        commands = [
            f'pacman --noconfirm --needed -Syu {" ".join(vm_default_packages)}'
        ]
        # auto reboot detection on kernel
        if reboot is None:
            commands.append('[[ "$(uname -r|sed -E "s|(.+)-hardened|\\1|")" = '
                            '   "$(pacman -Qs "^linux-hardened$"|head -1|cut -d" " -f2)" ]] '
                            f' || (echo "{reboot_message}" && systemctl reboot)')
        if reboot:
            print(reboot_message)
            commands.append('systemctl reboot')
        ssh(droplet, commands)


@command
def record(vm, data=None, type='A', ttl=60):
    vm = get(vm)[0]
    if data is None and type == 'A':
        data = vm.ip_address

    # check if there are existing records
    records = list(filter(lambda r: r.type == type and r.name == vm.name, get_records()))
    if records:
        record = records[0]
        # stop if the record is the same
        if record.data == data:
            return record
        # update record on mismatch
        record.data = data
        record.save()
        return record

    # create new record
    record = Record(ctf_domain, type=type, name=vm.name, data=data, ttl=ttl, token=TOKEN)
    record.create()
    return record


@command
def get_records():
    domain = Domain.get_object(TOKEN, ctf_domain)
    return domain.get_records()

from os.path import abspath
from os.path import dirname
from os.path import normpath

basedir = abspath(dirname(normpath(dirname(__file__))))

ssh_username = 'root'
ssh_port = 22
ssh_timeout = 5

vm_bootstrap_timeout = 300

vm_default_packages = ['vim',
                       'docker',
                       'lsof',
                       'wget',
                       'curl',
                       'gnu-netcat',
                       'procps-ng',
                       'htop',
                       'termite-terminfo',
                       'rxvt-unicode-terminfo']

ctf_domain = 'ctf.hackover.de'

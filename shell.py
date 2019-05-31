from termios import tcgetattr
from termios import tcsetattr
from termios import TCSADRAIN
from termios import TIOCGWINSZ
from sys import stdin
from sys import stdout
from select import select
from socket import timeout
from tty import setraw
from tty import setcbreak
from struct import unpack
from struct import pack
from fcntl import ioctl

from IPython.terminal.prompts import Prompts
from IPython.terminal.prompts import Token

from colorama import Fore
from colorama import Style

banner = """
    ___       ___       ___       ___       ___       ___
   /\  \     /\  \     /\  \     /\  \     /\  \     /\__\\
  /::\  \    \:\  \   /::\  \   /::\  \    \:\  \   /:/  /
 /:/\:\__\   /::\__\ /::\:\__\ /:/\:\__\   /::\__\ /:/__/
 \:\ \/__/  /:/\/__/ \/\:\/__/ \:\ \/__/  /:/\/__/ \:\  \\
  \:\__\    \/__/       \/__/   \:\__\    \/__/     \:\__\\
   \/__/                         \/__/               \/__/
"""


class CTFPrompt(Prompts):
    def in_prompt_tokens(self, cli=None):
        return [
            (Token, ''),
            (Token.Prompt, '>> ')]

    def out_prompt_tokens(self):
        return [
            (Token, ''),
            (Token.OutPrompt, '')]


def sigwinch_passthrough(pexpect_child):
    def callback(sig, data):
        s = pack("HHHH", 0, 0, 0, 0)
        a = unpack('hhhh', ioctl(stdout.fileno(), TIOCGWINSZ, s))
        global p
        pexpect_child.setwinsize(a[0], a[1])
    return callback


def posix_socket_shell(chan):
    oldtty = tcgetattr(stdin)
    try:
        setraw(stdin.fileno())
        setcbreak(stdin.fileno())
        chan.settimeout(0.0)

        while True:
            r, w, e = select([chan, stdin], [], [])
            if chan in r:
                try:
                    x = chan.recv(1024).decode()
                    if len(x) == 0:
                        # EOF
                        break
                    stdout.write(x)
                    stdout.flush()
                except timeout:
                    pass
            if stdin in r:
                x = stdin.read(1)
                if len(x) == 0:
                    break
                chan.send(x)

    finally:
        tcsetattr(stdin, TCSADRAIN, oldtty)


def query_yes_no(question, default='no'):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            stdout.write("Please respond with 'yes' or 'no' "
                         "(or 'y' or 'n').\n")


def red(s):
    return Fore.RED + s + Fore.RESET


def green(s):
    return Fore.GREEN + s + Fore.RESET


def yellow(s):
    return Fore.YELLOW + s + Fore.RESET


def bright(s):
    return Style.BRIGHT + s + Style.RESET_ALL


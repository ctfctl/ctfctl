from time import sleep
from time import time
from itertools import cycle
from random import choice
from math import ceil
from socket import timeout as TimeoutException


cycle_spinner = cycle('—\\|/')
cycle_baloon = cycle('.oO@Oo')
cycle_boxes = cycle('▖▘▝▗')
cycle_edges = cycle('┤┘┴└├┌┬┐')
cycle_all = [cycle_spinner, cycle_baloon, cycle_boxes, cycle_edges]


def transfer_status(f):
    def status(cur, total):
        print(f"\r[{int(cur/total*100):>3}%] {f}", end='', flush=True)
    return status


def print_status_string(string='.'):
    """Prints a string to stdout without newline, mostly usefull for
       progress status updates.

    optional:
    - string - str : string to print (default: '.')
    """
    print(string, end='', flush=True)


def print_status_cycle(labal='', status_cycle=None):
    status_cycle = status_cycle or choice(cycle_all)

    def callback():
        print(f'\r[{next(status_cycle)}] {labal}', end='', flush=True)
    return callback


def get_expose_port(challenge_path):
    with open(f'{challenge_path}/Dockerfile') as f:
        return next(iter(filter(
            lambda line: line.startswith('EXPOSE '),
            f.read().splitlines()))).split()[1]


def droplet_action_wait(action, update_wait=1, callback=print_status_string,
                        callback_wait=0.2, timeout=0):
    """wait until the action is marked as completed or with an error.

    optional:
    - update_wait - int : number of seconds to wait before
                          checking if the action is completed.
    - callback - func   : callback function that gets invoked
                          on while waiting.
    - callback_wait - float : number of seconds between callback
                              invocations.
    - timeout - float : timeout in seconds after which a timeout
                        exception will be raised (default: 0)

    return: true in case of success, false otherwise.
    """
    start = time()
    while action.status == u'in-progress':
        spin = update_wait / callback_wait
        for _ in range(ceil(spin)):
            if timeout and time() > start + timeout:
                raise TimeoutException(f"Operation exceeded {timeout} seconds")
            if callback:
                callback()
            sleep(update_wait / spin)
        action.load()

    return action.status == u'completed'

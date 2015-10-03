__author__ = 'Johnny Hujol'
__name__ = 'fabfile'

# Allow importing the code
import sys

sys.path.insert(0, './src')

import re
import stat
import string
import shutil

import datetime

import os
from os.path import expanduser

from fabric.operations import local

from security import SecurityHelper

from fabric.decorators import task

# this is to avoid the paramiko. error
import logging

logging.basicConfig()

"""
Methods for managing SSh
"""

SSH_CONFIG_FILE_NAME = 'config'

# Location of SSH files
SSH_DIR = expanduser("~") + os.sep + '.ssh' + os.sep

DIR_SRC = 'src'


@task(alias='uscf')
def update_ssh_config_file():
    """
    This method combines all config files into the SSh config file.
    """
    timestp = datetime.datetime.utcnow().strftime("%Y.%m.%d.%H.%M.%S")

    # Save the old config file.
    ssh_config_file = SSH_CONFIG_FILE_NAME

    ssh_file_sav = SSH_DIR + ssh_config_file + '.' + timestp + ".sav"
    shutil.copyfile(SSH_DIR + ssh_config_file, ssh_file_sav)
    os.chmod(ssh_file_sav, stat.S_IRUSR | stat.S_IWUSR)

    # combine all the *.config files into the config.
    file_names = os.listdir(SSH_DIR)
    prog = re.compile('.*\.config')
    config_appended = ''
    for file_name in file_names:
        matcher = prog.match(file_name)
        if matcher is not None:
            with open(SSH_DIR + file_name) as f:
                lines = f.readlines()
            if len(config_appended) != 0:
                config_appended += '\n\n'

            config_appended += string.join(lines, '')
    print config_appended

    # Write the combined configurations back into SSh config file.
    with open(SSH_DIR + ssh_config_file, 'w') as f:
        f.write(config_appended)


@task(alias='ssc')
def show_ssh_config():
    local('cat ' + SSH_DIR + SSH_CONFIG_FILE_NAME)


"""
Tasks to show, encrypt and decrypt the configs.
"""


def _get_security_helper():
    return SecurityHelper(
        'do_configs.json',
        os.path.join(os.path.dirname(os.path.realpath(__file__)), DIR_SRC),
        os.path.join(expanduser("~"), '.' + 'do_configs.json'),
        os.getenv('DO_CONFIG_FILE_PASSWORD')
    )


@task(alias='edc')
def encrypt_do_configs():
    """
    Encrypt the do_configs.json file from user's home directory.
    """
    _get_security_helper().encrypt_plain_file()


@task(alias='ddc')
def decrypt_do_configs():
    """
    Decrypt the do_configs.json file onto user's home directory.
    """
    _get_security_helper().decrypt_file()

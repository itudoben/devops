__author__ = 'hujol'
__name__ = 'security'

import base64
import os
import subprocess

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


class SecurityHelper:
    _encrypted_file = None
    _encrypted_file_path = None
    _plain_file_path = None

    # The password name to decrypt the data
    _encrypted_file_password = None

    def __init__(self, encrypted_file, encrypted_file_directory=None, plain_file_path=None,
                 encrypted_file_password=None):
        self._encrypted_file = encrypted_file
        self._encrypted_file_path = os.path.join(encrypted_file_directory, self._encrypted_file)
        self._plain_file_path = plain_file_path
        self._encrypted_file_password = encrypted_file_password

    def throws_exception_if_encrypted_file_password_not_set(self):
        if self._encrypted_file_password is None:
            raise Exception(
                'The encrypted file password is not defined. It is needed to decrypt the content of %s' %
                self._encrypted_file_path
            )

    def _get_cipher(self):
        ph = SHA256.new(self._encrypted_file_password).hexdigest()
        key = ph[:32]
        iv = ph[len(ph) - 16:]
        return AES.new(key, AES.MODE_CFB, iv)

    def encrypt_plain_file(self):
        """
        This method is used to encrypt the data in the file after editing it securely.
        """
        self.throws_exception_if_encrypted_file_password_not_set()

        with open(self._plain_file_path) as f:
            clear_text = ''.join(f.readlines())

        encoded = base64.b64encode(self._get_cipher().encrypt(clear_text))

        with open(self._encrypted_file_path, 'w+') as f:
            f.write(encoded)

        print '%s has been encrypted into %s' % (self._plain_file_path, self._encrypted_file_path)

    def decrypt_file(self):
        """
        This method is used to decrypt the data from the cipher text to be able to edit it in a secure way.
        """
        self.throws_exception_if_encrypted_file_password_not_set()

        with open(self._encrypted_file_path) as f:
            encrypted_text = ''.join(f.readlines())

        decoded = self._get_cipher().decrypt(base64.b64decode(encrypted_text))

        with open(self._plain_file_path, 'w') as f:
            f.write(decoded)

        # Set the file with the user permissions only on Linux and OS X.
        code_to_run = ['chmod', '700', self._plain_file_path]
        code_src = os.path.dirname(os.path.realpath(__file__))
        output = subprocess.check_output(code_to_run, cwd=code_src)

        print '%s has been decrypted into %s' % (self._encrypted_file_path, self._plain_file_path)

    def get_data(self):
        self.throws_exception_if_encrypted_file_password_not_set()

        with open(self._encrypted_file_path) as f:
            encrypted_text = ''.join(f.readlines())

        return self._get_cipher().decrypt(base64.b64decode(encrypted_text))

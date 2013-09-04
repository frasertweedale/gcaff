# This file is part of gcaff
# Copyright (C) 2013 Fraser Tweedale
#
# gcaff is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import os
import re
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)

(
    VALIDITY_NEW,
    VALIDITY_INVALID,
    VALIDITY_DISABLED,
    VALIDITY_REVOKED,
    VALIDITY_EXPIRED,
    VALIDITY_UNKNOWN,
    VALIDITY_UNDEFINED,
    VALIDITY_VALID,
    VALIDITY_MARGINAL,
    VALIDITY_FULL,
    VALIDITY_ULTIMATE,
) = range(11)

SIGNABLE = {
    VALIDITY_NEW: False,
    VALIDITY_INVALID: False,
    VALIDITY_DISABLED: False,
    VALIDITY_REVOKED: False,
    VALIDITY_EXPIRED: False,
    VALIDITY_UNKNOWN: True,
    VALIDITY_UNDEFINED: True,
    VALIDITY_VALID: True,
    VALIDITY_MARGINAL: True,
    VALIDITY_FULL: True,
    VALIDITY_ULTIMATE: True,
}

VALIDITY = {
    b'o': VALIDITY_NEW,
    b'i': VALIDITY_INVALID,
    b'd': VALIDITY_DISABLED,
    b'r': VALIDITY_REVOKED,
    b'e': VALIDITY_EXPIRED,
    b'-': VALIDITY_UNKNOWN,
    b'q': VALIDITY_UNDEFINED,
    b'n': VALIDITY_VALID,
    b'm': VALIDITY_MARGINAL,
    b'f': VALIDITY_FULL,
    b'u': VALIDITY_ULTIMATE,
}

ALGORITHM = {
    b'1':  'RSA',
    b'16': 'Elgamal (encrypt only)',
    b'17': 'DSA',
    b'20': 'Elgamal (sign and encrypt)',
}


class Uid(object):
    def __init__(self, validity, data):
        self._validity = validity
        self.data = data

    def validity(self):
        return VALIDITY.get(self._validity, VALIDITY_UNKNOWN)

    def signable(self):
        return SIGNABLE[self.validity()]


class TextUid(Uid):
    def name(self):
        return self._extract_parts()[0]

    def email(self):
        return self._extract_parts()[1]

    def _extract_parts(self):
        """Extract name and email address from the given uid."""
        match = re.match(r'(.*) <(.*?)>$', self.data)
        return match.group(1, 2) if match else (self.data, None)

    def __str__(self):
        return self.data


class ImageUid(Uid):
    def name(self):
        return '[image]'

    def email(self):
        return None

    def __str__(self):
        return '[jpeg image of size {}]'.format(len(self.data))


class Key(object):
    def __init__(self, length, algorithm, fingerprint, uids):
        self.length = length
        self.algorithm = algorithm
        self.fingerprint = fingerprint
        self.uids = uids

    def __eq__(self, other):
        return self.fingerprint == other.fingerprint

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def keyid(self):
        """Return the long key ID."""
        return self.fingerprint[-16:]

    def names(self):
        """Return a list of all names on non-image UIDs."""
        names = (
            uid.name() for uid in self.uids
            if isinstance(uid, TextUid) and uid.signable()
        )
        return filter(None, names)

    def name(self):
        """Get the first name on this key.

        Return a list containing the first name found on a
        valid UID, or the empty list if no such name is found.

        """
        return self.names()[:1]

    def emails(self):
        """Return a list of all valid email addresses on the key."""
        emails = (uid.email() for uid in self.uids if uid.signable())
        return filter(None, emails)

    def email(self):
        """Get a usable email address for this key.

        Return a list containing the first email address found on a
        valid UID, or the empty list if no such address is found.

        """
        return self.emails()[:1]

    def uid_email(self, i):
        """Get an email address for the given UID.

        If the given UID does not have an email address, return a
        list of all email addresses on the key, in the hope that
        one of them will suffice for contacting the emailless UID.

        """
        email = self.uids[i].email()
        return [email] if email else self.emails()

    def human_algorithm(self):
        return ALGORITHM.get(self.algorithm, '<unknown algorithm>')

    def human_fingerprint(self):
        fpr = self.fingerprint
        return ' '.join(fpr[i:i + 4] for i in xrange(0, len(fpr), 4))


class GnuPG(object):
    """GnuPG wrapper.

    Leaving ``homedir`` unspecified uses the "normal" keyring, i.e.
    GNUPGHOME if set, else the GnuPG default of ``$HOME/.gnupg``.

    The secret keyring from the "normal" homedir is always used, so
    signing keys do not have to be moved around.

    """
    def __init__(self, homedir=None):
        # determine the user's normal GNUPGHOME, where we expect
        # to find signing keys
        self.homedir = homedir \
            or os.environ.get('GNUPGHOME') \
            or os.path.join(os.environ['HOME'], '.gnupg')
        secdir = os.environ.get('GNUPGHOME') \
            or os.path.join(os.environ['HOME'], '.gnupg')
        self.secret_keyring = os.path.join(secdir, 'secring.gpg')

    def _popen(self, args):
        args = [
            'gpg',
            '--no-tty',
            '--use-agent',
            '--no-auto-check-trustdb',
            '--secret-keyring', self.secret_keyring,
        ] + args
        logger.info('execute gpg: GNUPGHOME={} {}'.format(self.homedir, args))
        return subprocess.Popen(
            args,
            env=dict(os.environ, GNUPGHOME=self.homedir),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    def import_keys(self, data, minimal=False):
        """Import keys from the given data.

        ``minimal``
            Do a minimal import.  Defaults to ``False``.

        """
        logger.info('import')
        args = ['--import']
        if minimal:
            args += ['--import-options', 'import-minimal']
        p = self._popen(args)
        stdout, stderr = p.communicate(data)
        logger.debug('gpg --import exited code {!r}'.format(p.returncode))

    def export_keys(self, keyids=None, minimal=False):
        """Export the given keys, returning the armoured data."""
        logger.info('export; keyids: {!r}'.format(keyids))
        opts = 'export-minimal' if minimal \
            else 'no-export-minimal,no-export-clean'
        p = self._popen([
            '--armor',
            '--export',
            '--export-options', opts,
        ] + (keyids or []))
        stdout, stderr = p.communicate()
        if p.returncode != 0:
            raise RuntimeError('gpg --export returned nonzero')
        return stdout

    def encrypt(self, keyid, data):
        """Encrypt ``data`` to the given ``keyid`` (with armour)."""
        logger.info('encrypt; recipient: {}'.format(keyid))
        p = self._popen([
            '--armor',
            '--trust-model', 'always',
            '--encrypt',
            '--no-encrypt-to',
            '--recipient', keyid
        ])
        stdout, stderr = p.communicate(data)
        if p.returncode != 0:
            raise RuntimeError(
                'gpg --encrypt returned {}'.format(p.returncode)
            )
        return stdout

    def list_secret_keys(self, keyids=None):
        keys = self._list_keys(keyids, secret=True)
        return self._list_keys([k.keyid for k in keys])

    def list_keys(self, keyids=None):
        return self._list_keys(keyids)

    def _list_keys(self, keyids=None, secret=False):
        """Retrieve the given key."""
        # FIXME secret keys are not displaying validity
        rstat_fd, wstat_fd = os.pipe()
        rattr_fd, wattr_fd = os.pipe()
        p = self._popen([
            '--status-fd', str(wstat_fd),
            '--attribute-fd', str(wattr_fd),
            '--fingerprint',
            '--with-colons',
            '--list-secret-keys' if secret else '--list-keys',
            '--list-options', 'show-uid-validity,show-unusable-uids',
        ] + (keyids or []))
        stdout, stderr = p.communicate()
        os.close(wstat_fd)
        os.close(wattr_fd)
        with os.fdopen(rstat_fd) as f:
            statout = f.read()
        images = self._get_images_from_key(statout, rattr_fd)
        os.close(rattr_fd)

        keys = []
        seen = 0
        kwargs = {'uids': []}
        for line in stdout.splitlines():
            if line.startswith('sec' if secret else 'pub'):
                if seen:
                    keys.append(Key(**kwargs))
                    kwargs = {'uids': []}
                _, _, kwargs['length'], kwargs['algorithm'] \
                    = line.split(':')[:4]
                seen += 1
            if line.startswith('fpr'):
                kwargs['fingerprint'] = line.split(':')[9]
            elif line.startswith('uid') or line.startswith('pub'):
                _, validity, _, _, _, _, _, _, _, data = line.split(':')[:10]
                if data:
                    kwargs['uids'].append(TextUid(validity, data))
            elif line.startswith('uat'):
                # if uat lines that are NOT jpeg images are listed,
                # this code is wrong and needs fixing.  But I have
                # never seen such a case.
                #
                _, validity = line.split(':')[:2]
                kwargs['uids'].append(ImageUid(validity, data=images.pop(0)))
        if seen:
            keys.append(Key(**kwargs))
        return keys

    @staticmethod
    def _get_images_from_key(statout, fd):
        images = []
        for line in statout.splitlines():
            match = re.match(r'''
                    \[GNUPG:\]\ ATTRIBUTE
                    \ \w+                   # fingerprint
                    \ (?P<octets>\d+)
                    \ 1                     # type (1 == image)
                    \ (?P<index>\d+)
                    \ (?P<count>\d+)
                    \                       # ... don't care about the rest
                ''', line, re.VERBOSE)
            if match:
                data = os.read(fd, int(match.group('octets')))
                if not data[:4] == '\x10\x00\x01\x01':
                    raise RuntimeError('invalid data in attribute packet')
                if match.group('index') == '1':
                    images.append(data[16:])
                else:
                    images[-1] += data[16:]
        return images

    STATE_MINIMIZE, STATE_INIT, STATE_UID, STATE_SIGN, STATE_SAVE = range(5)

    def sign_key_uid(
        self, signkey, keyid, uid, cert_level=0, digest='SHA256',
        minimize=False
    ):
        """Sign the given uid on the specified key.

        ``signkey``
            ID of the key to be used for signing.  The key must be
            present on both the secret keyring and this GnuPG's
            public keyring.
        ``keyid``
            ID of the key to be signed.
        ``uid``
            Integer uid.  Note that uids count from ZERO.

        """
        # TODO configure cert-digest-algo
        self.uid = uid
        self.state = self.STATE_MINIMIZE if minimize else self.STATE_INIT
        p = self._popen([
            '--command-fd', '0',
            '--status-fd', '1',
            '--default-cert-level', str(cert_level),
            '--no-ask-cert-level',
            '--cert-digest-algo', 'SHA256',
            '--local-user', signkey,
            '--edit-key', keyid
        ])
        while p.poll() is None:
            line = p.stdout.readline().strip()
            logger.debug(line)
            response = self._get_response(line)
            if response is not None:
                logger.debug(response)
                p.stdin.write(response + '\n')
            # TODO set a max number of iteration and die if
            # exceeded, so we don't get stuck in loop?
        logger.info('gpg process exited code {}'.format(p.returncode))
        if p.returncode != 0:
            raise RuntimeError("Bad passphrase")

    def _get_response(self, line):
        msg = line[9:]  # strip "[GNUPG:] "
        lut = {
            "GOT_IT": None,
            "GET_LINE keyedit.prompt": self._get_line_keyedit_prompt,
            "GET_LINE sign_uid.class": '',  # accept default
            "GET_BOOL sign_uid.okay": 'y',
            # "USERID_HINT <full user id>"
            # "NEED_PASSPHRASE <long keyid> <longkeyid> 1 0"
            # "BAD_PASSPHRASE <long keyid>" <-- long keyid; exit code 2
            # "ALREADY_SIGNED <long keyid>" <-- exit code 0
        }
        try:
            response = lut[msg]
        except KeyError:
            logger.debug('ignore unrecognised message: {!r}'.format(msg))
            return None
        return response() if callable(response) else response

    def _get_line_keyedit_prompt(self):
        if self.state == self.STATE_MINIMIZE:
            self.state = self.STATE_INIT
            return 'minimize'
        if self.state == self.STATE_INIT:
            self.state = self.STATE_UID
            return '{}'.format(self.uid + 1)
        elif self.state == self.STATE_UID:
            self.state = self.STATE_SIGN
            return 'sign'
        elif self.state == self.STATE_SIGN:
            self.state = self.STATE_SAVE
            return 'save'
        else:
            raise RuntimeError('gpg state violation')


class AgentError(StandardError):
    pass


def test_agent():
    """Try to talk to the agent and raise an error if we can't."""
    try:
        p = subprocess.Popen(
            ['gpg-connect-agent'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate()
        if p.returncode != 0:
            raise AgentError(stderr)
    except OSError as e:
        raise AgentError(str(e))

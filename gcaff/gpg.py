# This file is part of gcaff
# Copyright (C) 2013, 2014, 2016, 2017  Fraser Tweedale
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
    b'18': 'ECDH',
    b'19': 'ECDSA',
    b'20': 'Elgamal (sign and encrypt)',
    b'22': 'EdDSA',
}

ECC_ALGORITHMS = {'18', '19', '22'}


class Uid(object):
    def __init__(self, validity_char, data):
        self.validity_char = validity_char
        self.data = data

    def validity(self):
        return VALIDITY.get(self.validity_char, VALIDITY_UNKNOWN)

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


class UnknownUid(Uid):
    def name(self):
        return '[unknown attribute]'

    def signable(self):
        return False

    def email(self):
        return None

    def __str__(self):
        return '[unknown attribute of size {}]'.format(len(self.data))


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
        return '{} ({}{})'.format(
            ALGORITHM.get(self.algorithm, '<unknown algorithm>'),
            self.length,
            '-bit' if self.algorithm not in ECC_ALGORITHMS else ''
        )

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
    def _probe():
        for exe in ['gpg2', 'gpg']:
            try:
                return exe, subprocess.check_output([exe, '--version'])
            except OSError as e:
                exc = e
        raise e

    exe, version = _probe()
    default_gnupghome = (
        os.environ.get('GNUPGHOME')
        or os.path.join(os.environ['HOME'], '.gnupg')
    )

    def __init__(self, homedir=None):
        gnupghome = homedir or self.default_gnupghome

        if os.path.isdir(
                os.path.join(self.default_gnupghome, 'private-keys-v1.d')):
            # --secret-keyring option is obsolete and ignored.
            # We have to use default GNUPGHOME but suppress use of
            # default keyring and use the keyring in self.homedir
            self.homedir = self.default_gnupghome
            self.keyring_args = [
                '--no-default-keyring',
            ]

            gpg_db = os.path.join(gnupghome, 'pubring.gpg')
            have_gpg_db = os.path.isfile(gpg_db)
            kbx_db = os.path.join(gnupghome, 'pubring.kbx')
            have_kbx_db = os.path.isfile(kbx_db) or not have_gpg_db

            if have_gpg_db:
                self.keyring_args.extend(['--keyring', gpg_db])
            if have_kbx_db:
                self.keyring_args.extend(['--keyring', kbx_db])

        else:
            self.homedir = gnupghome
            self.keyring_args = [
                '--secret-keyring',
                    os.path.join(self.default_gnupghome, 'secring.gpg'),
            ]

    def _popen(self, args):
        args = [
            self.exe,
            '--no-tty',
            '--use-agent',
            '--no-auto-check-trustdb',
        ] + self.keyring_args + args
        logger.info('execute gpg: GNUPGHOME={} {}'.format(self.homedir, args))
        return subprocess.Popen(
            args,
            env=dict(os.environ, GNUPGHOME=self.homedir),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    def agent_socket(self):
        """Return path to agent socket if using the standard socket."""
        path = os.path.join(self.homedir, 'S.gpg-agent')
        return path if os.path.exists(path) else None

    def unlock_key(self, signkey):
        """Force user to unlock their key by signing some empty data."""
        args = [
            '--local-user',
            signkey,
            '--armor',
            '--output=/dev/null',
            '--sign',
            '/dev/null'
        ]
        p = self._popen(args)
        p.communicate()
        return p.returncode == 0

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
        """Retrieve the given key(s)."""

        # create temporary files for status and attribute info
        stat_fh = tempfile.NamedTemporaryFile()
        attr_fh = tempfile.NamedTemporaryFile()

        # FIXME secret keys are not displaying validity
        p = self._popen([
            '--status-file', stat_fh.name,
            '--attribute-file', attr_fh.name,
            '--fingerprint',
            '--with-colons',
            '--list-secret-keys' if secret else '--list-keys',
            '--list-options', 'show-uid-validity,show-unusable-uids',
        ] + (keyids or []))

        stdout, stderr = p.communicate()

        images = self._get_images_from_key(stat_fh, attr_fh)

        keys = []
        seen = 0
        kwargs = {'uids': []}
        for line in stdout.splitlines():
            if line.startswith('sec' if secret else 'pub'):
                if seen:
                    keys.append(Key(**kwargs))
                    kwargs = {'uids': []}
                fields = line.split(':')
                kwargs['algorithm'] = fields[3]
                if kwargs['algorithm'] in ECC_ALGORITHMS:
                    kwargs['length'] = fields[16]  # ECC curve name
                else:
                    kwargs['length'] = fields[2]
                seen += 1
            if line.startswith('fpr') and 'fingerprint' not in kwargs:
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
                uid = images.pop(0)
                uid.validity_char = validity
                kwargs['uids'].append(uid)
        if seen:
            keys.append(Key(**kwargs))
        return keys

    @staticmethod
    def _get_images_from_key(stat_fh, attr_fh):
        images = []
        for line in stat_fh.read().splitlines():
            match = re.match(r'''
                    \[GNUPG:\]\ ATTRIBUTE
                    \ \w+                   # fingerprint
                    \ (?P<octets>\d+)
                    \ (?P<attrtype>\d+)
                    \ (?P<index>\d+)
                    \ (?P<count>\d+)
                    \                       # ... don't care about the rest
                ''', line, re.VERBOSE)
            if match:
                data = attr_fh.read(int(match.group('octets')))

                offset = 0
                con = UnknownUid

                if match.group('attrtype') == '1':  # image
                    offset = 16
                    if data[:4] == '\x10\x00\x01\x01':  # JPEG
                        con = ImageUid

                if match.group('index') == '1':
                    images.append(con(None, data[offset:]))
                else:
                    images[-1].data += data[offset:]

        return images

    STATE_MINIMIZE, STATE_INIT, STATE_UID, STATE_SIGN, \
        STATE_GOODPW, STATE_BADPW, STATE_NOPW, STATE_DONE, \
        STATE_NOAGENT, STATE_INV_SGNR = range(10)

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
            response = self._get_response(signkey, line)
            if response is not None:
                logger.debug(response)
                p.stdin.write(response + '\n')
            # TODO set a max number of iteration and die if
            # exceeded, so we don't get stuck in loop?
        logger.info('gpg process exited code {}'.format(p.returncode))
        if self.state == self.STATE_BADPW:
            raise RuntimeError("Incorrect passphrase")
        elif self.state == self.STATE_NOPW:
            raise RuntimeError("Passphase not supplied")
        elif self.state == self.STATE_NOAGENT:
            raise RuntimeError("Failed to locate gpg-agent")
        elif self.state == self.STATE_INV_SGNR:
            raise RuntimeError("Invalid signing key")
        elif self.state != self.STATE_DONE:
            raise RuntimeError("Unhandled GnuPG behaviour")

    def _get_response(self, signkey, line):
        msg = line[9:]  # strip "[GNUPG:] "
        lut = {
            "GOT_IT": None,
            "GET_LINE keyedit.prompt": self._get_line_keyedit_prompt,
            "GET_LINE sign_uid.class": '',  # accept default
            "GET_BOOL sign_uid.okay": 'y',
            "GET_BOOL keyedit.save.okay": 'n',
            "BAD_PASSPHRASE {}".format(signkey): self._on_bad_passphrase,
            "MISSING_PASSPHRASE": self._on_missing_passphrase,
            "GOOD_PASSPHRASE": self._on_good_passphrase,
            "GET_HIDDEN passphrase.enter": self._on_passphrase_enter,
            "INV_SGNR 9 {}".format(signkey): self._on_INV_SGNR,
            # "USERID_HINT <full user id>"
            # "NEED_PASSPHRASE <long keyid> <longkeyid> 1 0"
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
        elif self.state in {
            self.STATE_BADPW,
            self.STATE_NOPW,
            self.STATE_NOAGENT,
            self.STATE_INV_SGNR,
        }:
            return 'quit'
        elif self.state in {self.STATE_SIGN, self.STATE_GOODPW}:
            self.state = self.STATE_DONE
            return 'save'
        else:
            raise RuntimeError('gpg state violation')

    def _on_bad_passphrase(self):
        if self.state not in {self.STATE_NOPW, self.STATE_NOAGENT}:
            self.state = self.STATE_BADPW

    def _on_missing_passphrase(self):
        if self.state != self.STATE_NOAGENT:
            self.state = self.STATE_NOPW

    def _on_INV_SGNR(self):
        self.state = self.STATE_INV_SGNR

    def _on_good_passphrase(self):
        self.state = self.STATE_GOODPW

    def _on_passphrase_enter(self):
        self.state = self.STATE_NOAGENT
        return ''


class AgentError(StandardError):
    pass


def test_agent():
    try:
        _test_connect_agent()
    except AgentError:
        _start_agent()
        _test_connect_agent()


def _test_connect_agent():
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


def _start_agent():
    """Start a ``gpg-agent`` process.

    Does not check to see if an agent is already running, and does
    not raise if there is an error (caller should call
    ``_test_connect_agent`` to determine if a working agent is
    running.

    """
    try:
        subprocess.check_call(['gpg-agent', '--daemon', '--use-standard-socket'])
    except:
        pass

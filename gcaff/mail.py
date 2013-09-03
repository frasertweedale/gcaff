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

"""
Generate and send PGP/MIME messages.

Note that the "uid" in subroutines that take such an argument is a
full uid string.  Selecting a uid for uids that do not have an email
address is outside the scope of this module.

"""

import email.encoders
import email.mime.application
import email.mime.multipart
import email.mime.text
import logging
import smtplib

from . import version

logger = logging.getLogger(__name__)

TEMPLATE = u"""
Hi,

please find attached the user id

  {signee_uid}

of your key {signee_keyid} signed by me.

If you have multiple user ids, I sent the signature for each user id
separately to that user id's associated email address. You can
import the signatures by running each through `gpg --import`.

Note that I did not upload your key to any keyservers. If you want
this new signature to be available to others, please upload it
yourself.  With GnuPG this can be done using

  gpg --keyserver pool.sks-keyservers.net --send-key {signee_keyid}

If you have any questions, don't hesitate to ask.

Regards,

{signer_name}
"""


def test_smtp():
    server = smtplib.SMTP('localhost')
    server.quit()


def create_message(
    gpg,
    payload,
    _from,
    _tos,
    signer_name,
    signee_keyid,
    signee_uid,
):
    """Create and return a PGP/MIME message and sender and recipient details.

    The return value is a 3-tuple consisting of:

    * "From" address
    * list of "To" addresses (which contains just the signee's address)
    * message as a bytestring

    An accumulation of such tuples is precisely the argument format
    required by ``send_messages``.

    """
    cleartext = _create_message(signee_keyid, signee_uid, signer_name, payload)
    msg = _encrypt_message(gpg, signee_keyid, cleartext)
    msg['From'] = _from
    msg['To'] = ', '.join(_tos)
    msg['Subject'] = 'Your signed PGP key 0x{}'.format(signee_keyid)
    msg['User-Agent'] = version.USER_AGENT
    return _from, _tos, msg.as_string()


def send_messages(msgs):
    """Generator that sends emails and yields progress."""
    server = smtplib.SMTP('localhost')
    for i, (_from, _tos, msg) in enumerate(msgs):
        server.sendmail(_from, _tos, msg)
        yield i + 1
    server.quit()


def _create_message(signee_keyid, signee_uid, signer_name, payload):
    text_plain = email.mime.text.MIMEText(
        TEMPLATE.format(
            signee_keyid=signee_keyid,
            signee_uid=signee_uid,
            signer_name=signer_name
        ),
        'plain',
        'utf-8'
    )
    application_pgp_keys = email.mime.application.MIMEApplication(
        payload,
        'pgp-keys',
        email.encoders.encode_7or8bit
    )
    multipart = email.mime.multipart.MIMEMultipart('mixed')
    multipart.attach(text_plain)
    multipart.attach(application_pgp_keys)
    return str(multipart)


def _encrypt_message(gpg, keyid, cleartext):
    application_pgp_encrypted = email.mime.application.MIMEApplication(
        b'Version: 1',
        'pgp-encrypted',
        email.encoders.encode_7or8bit
    )
    application_octet_stream = email.mime.application.MIMEApplication(
        gpg.encrypt(keyid, cleartext),
        'octet-stream',
        email.encoders.encode_7or8bit
    )
    multipart = email.mime.multipart.MIMEMultipart(
        'encrypted',
        protocol='application/pgp-encrypted'
    )
    multipart.attach(application_pgp_encrypted)
    multipart.attach(application_octet_stream)
    return multipart

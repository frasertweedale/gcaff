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

from __future__ import division

import contextlib
import logging
import multiprocessing
import os
import tempfile

import gobject
import gtk

from . import gpg
from . import mail
from . import version

logger = logging.getLogger(__name__)


class SigningAssistant(gtk.Assistant):
    def __init__(self, usergpg, tmpgpg):
        super(SigningAssistant, self).__init__()
        self.set_title(version.USER_AGENT)
        self.connect('delete-event', gtk.main_quit)
        self.connect('cancel', gtk.main_quit)
        self.connect('close', gtk.main_quit)
        self.connect('prepare', self.on_prepare)

        self.signing_keys_by_keyid = {
            key.keyid: key
            for key in usergpg.list_secret_keys()
        }
        signing_keys = self.signing_keys_by_keyid.values()

        self.signing_keys = []
        self.signing_key_page = SigningKeyPage(signing_keys)
        self.append_page(self.signing_key_page)
        self.set_page_type(self.signing_key_page, gtk.ASSISTANT_PAGE_CONTENT)
        self.set_page_title(self.signing_key_page, 'Select signing key(s).')
        self.signing_key_page.connect(
            'signing-keys-changed',
            self.on_signing_keys_changed
        )

        keys = (
            key for key in tmpgpg.list_keys()
            if key not in signing_keys
        )

        self.uid_selectors = []
        for key in keys:
            # TODO skip signing key
            uid_selector = UidSelector(key)
            self.append_page(uid_selector)
            self.set_page_type(uid_selector, gtk.ASSISTANT_PAGE_CONTENT)
            self.set_page_title(uid_selector, key.human_fingerprint())
            self.uid_selectors.append((key, uid_selector))

        confirm_page = ConfirmPage()
        self.append_page(confirm_page)
        self.set_page_type(confirm_page, gtk.ASSISTANT_PAGE_CONFIRM)

        # path to signature file
        self.sigfile = None

        self.progress_page = ProgressPage(usergpg, tmpgpg)
        self.append_page(self.progress_page)
        self.set_page_type(self.progress_page, gtk.ASSISTANT_PAGE_PROGRESS)
        self.progress_page.connect('sign-complete', self.on_sign_complete)
        self.progress_page.connect('send-complete', self.on_send_complete)

        summary_page = SummaryPage(self.progress_page)
        self.append_page(summary_page)
        self.set_page_type(summary_page, gtk.ASSISTANT_PAGE_SUMMARY)

    def _selected_uids(self):
        selected_uids = (
            (key, uid_selector.selected_uids())
            for key, uid_selector in self.uid_selectors
        )
        return [(key, sel) for key, sel in selected_uids if sel]

    def on_signing_keys_changed(self, page, keyids):
        self.signing_keys = \
            [self.signing_keys_by_keyid[keyid] for keyid in keyids]
        self.set_page_complete(self.signing_key_page, bool(keyids))

    def on_send_complete(self, page):
        self.set_page_complete(self.progress_page, True)

    def on_sign_complete(self, page, sigfile):
        self.sigfile = sigfile

    @staticmethod
    def on_prepare(assistant, page, *args):
        on_complete = lambda: assistant.set_page_complete(page, True)
        if isinstance(page, ProgressPage):
            page.sign_and_send(
                assistant.signing_keys,
                assistant._selected_uids()
            )
        elif not isinstance(page, SigningKeyPage):
            assistant.set_page_complete(page, True)


class SigningKeyPage(gtk.VBox):
    __gsignals__ = {
        'signing-keys-changed': (
            gobject.SIGNAL_RUN_FIRST, gobject.TYPE_NONE, (object,)
        ),
    }

    def __init__(self, keys):
        super(SigningKeyPage, self).__init__()

        self.model = gtk.ListStore(bool, str, str, str)
        for key in keys:
            self.model.append((
                False,
                key.length,
                key.human_algorithm(),
                key.keyid,
            ))

        treeview = gtk.TreeView(self.model)
        self.pack_start(treeview)

        toggle_renderer = gtk.CellRendererToggle()
        toggle_renderer.connect('toggled', self.on_toggle, self.model)
        use_col = gtk.TreeViewColumn('Sign with?')
        use_col.pack_start(toggle_renderer, True)
        use_col.set_attributes(toggle_renderer, active=0)
        treeview.append_column(use_col)

        text_renderer = gtk.CellRendererText()
        length_col = gtk.TreeViewColumn('Length')
        length_col.pack_start(text_renderer, True)
        length_col.set_attributes(text_renderer, text=1)
        treeview.append_column(length_col)

        text_renderer = gtk.CellRendererText()
        algo_col = gtk.TreeViewColumn('Algorithm')
        algo_col.pack_start(text_renderer, True)
        algo_col.set_attributes(text_renderer, text=2)
        treeview.append_column(algo_col)

        text_renderer = gtk.CellRendererText()
        keyid_col = gtk.TreeViewColumn('Key ID')
        keyid_col.pack_start(text_renderer, True)
        keyid_col.set_attributes(text_renderer, text=3)
        treeview.append_column(keyid_col)

    def on_toggle(self, cell, path, model):
        model[path][0] = not model[path][0]
        signing_keys = [keyid for checked, _, _, keyid in model if checked]
        self.emit('signing-keys-changed', signing_keys)


class UidSelector(gtk.VBox):
    """Select UIDs on a key."""
    def __init__(self, key):
        super(UidSelector, self).__init__(spacing=10)
        self.set_border_width(10)

        self.cert_level = 0
        frame = gtk.Frame('Certification level')
        hbox = gtk.HBox()
        button_box = gtk.VButtonBox()
        button_box.set_border_width(5)
        button_box.set_spacing(-10)
        radio0 = gtk.RadioButton(None, '(0) I will not answer.')
        radio0.connect('clicked', self.on_radio_clicked, 0)
        radio1 = gtk.RadioButton(radio0, '(1) I have not checked at all.')
        radio1.connect('clicked', self.on_radio_clicked, 1)
        radio2 = gtk.RadioButton(radio0, '(2) I have done casual checking.')
        radio2.connect('clicked', self.on_radio_clicked, 2)
        radio3 = gtk.RadioButton(
            radio0,
            '(3) I have done very careful checking.'
        )
        radio3.connect('clicked', self.on_radio_clicked, 3)
        for radio in (radio0, radio1, radio2, radio3):
            button_box.add(radio)
        hbox.pack_start(button_box, expand=False)
        frame.add(hbox)
        self.pack_start(frame, expand=False)

        self.OFFSET = dict(zip(
            (
                'INDEX',
                'SELECTED',
                'SELECTABLE',
                'NOT_SELECTABLE',
                'TEXT',
                'PHOTO',
            ),
            range(6)
        ))
        self.model = gtk.ListStore(int, bool, bool, bool, str, gtk.gdk.Pixbuf)

        self.uids = key.uids
        for i, uid in enumerate(key.uids):
            if isinstance(uid, gpg.TextUid):
                label = uid.data
                pixbuf = None
            else:
                label = None
                with tempfile.NamedTemporaryFile() as f:
                    f.write(uid.data)
                    f.flush()
                    pixbuf = gtk.gdk.pixbuf_new_from_file(f.name)
            self.model.append((
                i,
                False,
                uid.signable(),
                not uid.signable(),
                label,
                pixbuf,
            ))

        treeview = gtk.TreeView(self.model)

        sign_col = gtk.TreeViewColumn('Sign?')
        toggle_renderer = gtk.CellRendererToggle()
        sign_col.pack_start(toggle_renderer, True)
        sign_col.set_attributes(
            toggle_renderer,
            activatable=self.OFFSET['SELECTABLE'],
            active=self.OFFSET['SELECTED']
        )
        toggle_renderer.connect('toggled', self.on_toggle, self.model)
        treeview.append_column(sign_col)

        uid_col = gtk.TreeViewColumn('UID')
        text_renderer = gtk.CellRendererText()
        uid_col.pack_start(text_renderer, True)
        uid_col.set_attributes(
            text_renderer,
            text=self.OFFSET['TEXT'],
            strikethrough=self.OFFSET['NOT_SELECTABLE']
        )
        pixbuf_renderer = gtk.CellRendererPixbuf()
        uid_col.pack_start(pixbuf_renderer, True)
        uid_col.set_attributes(pixbuf_renderer, pixbuf=self.OFFSET['PHOTO'])
        treeview.append_column(uid_col)
        # TODO column showing validity

        self.pack_start(treeview, expand=False)

    def on_toggle(self, cell, path, model):
        model[path][self.OFFSET['SELECTED']] \
            = not model[path][self.OFFSET['SELECTED']]

    def on_radio_clicked(self, button, cert_level):
        self.cert_level = cert_level

    def selected_uids(self):
        uids = []
        for row in self.model:
            if row[self.OFFSET['SELECTED']]:
                uids.append((
                    row[self.OFFSET['INDEX']],
                    self.uids[row[self.OFFSET['INDEX']]],
                    self.cert_level
                ))
        return uids


class ConfirmPage(gtk.HBox):
    def __init__(self):
        super(ConfirmPage, self).__init__()
        text = '''Sign and email all selected UIDs?'''
        self.pack_start(gtk.Label(text))


def sign_and_send(tmpgpg, uids, conn):
    """Sign and send signatures, sending results into the pipe."""
    n = len(uids) * 2
    c = 0
    signatures = []
    for i, (signargs, _) in enumerate(uids):
        logger.info('signing key, signargs={}'.format(signargs))
        try:
            tmpgpg.sign_key_uid(*signargs, minimize=True)
            signature = tmpgpg.export_keys([signargs[1]])
            logger.info('got signature: {}'.format(signature))
        except:
            logger.exception('error signing key: {}'.format(signargs))
            signature = None
        signatures.append(signature)
        c += 1
        conn.send((
            c / n,
            (True, None) if signature is not None else (False, 'sig fail')
        ))

    sigfile = _write_signatures(signatures)
    logger.warn('wrote signatures to file: {}'.format(sigfile))
    conn.send((None, sigfile))

    def _create_message(sig, mailargs):
        try:
            return mail.create_message(tmpgpg, sig, *mailargs)
        except Exception as e:
            e.mailargs = mailargs
            return e

    emails = [
        _create_message(sig, mailargs) if sig else None
        for (_, mailargs), sig in zip(uids, signatures)
    ]
    good_emails = filter(lambda x: not isinstance(x, Exception), emails)
    bad_emails = filter(lambda x: isinstance(x, Exception), emails)
    logger.info('failed to create {} emails'.format(len(bad_emails)))
    for e in bad_emails:
        c += 1
        conn.send((c / n, (False, e)))
    logger.info('sending {} emails'.format(len(good_emails)))
    for i in mail.send_messages(good_emails):
        c += 1
        conn.send((c / n, (True, None)))
    conn.send((1.0, (True, True)))


@contextlib.contextmanager
def _closing_mkstemp():
    fd, name = tempfile.mkstemp()
    try:
        yield fd, name
    finally:
        os.close(fd)


def _write_signatures(signatures):
    with _closing_mkstemp() as (fd, name):
        os.write(fd, '\n'.join(sig for sig in signatures if sig))
        return name


class ProgressPage(gtk.VBox):
    __gsignals__ = {
        'sign-complete': (gobject.SIGNAL_RUN_FIRST, gobject.TYPE_NONE, (str,)),
        'send-complete': (gobject.SIGNAL_RUN_FIRST, gobject.TYPE_NONE, ()),
    }

    def __init__(self, usergpg, tmpgpg):
        super(ProgressPage, self).__init__()
        self.usergpg = usergpg
        self.tmpgpg = tmpgpg
        self.progress_bar = gtk.ProgressBar()
        self.pack_start(self.progress_bar)

        self.notice = gtk.Label()
        self.notice.set_selectable(True)
        self.pack_start(self.notice)

        self.connect('sign-complete', self.on_sign_complete)

    def sign_and_send(self, signing_keys, uids):
        sign_ids = [key.keyid for key in signing_keys]
        logger.debug('import signing keys from user gpg: {}'.format(sign_ids))
        self.tmpgpg.import_keys(
            self.usergpg.export_keys(sign_ids, minimal=True)
        )

        logger.debug('normalising keylist: {}'.format(uids))
        spec = [
            (
                (signkey.keyid, key.keyid, uid_index, cert_level),
                (
                    signkey.email()[0] if signkey.email() else None,
                    key.uid_email(uid_index),
                    signkey.name()[0] if signkey.name() else None,
                    key.keyid,
                    str(key.uids[uid_index])
                ),
            )
            for signkey in signing_keys
            for key, keyuids in uids
            for uid_index, uid, cert_level in keyuids
        ]
        logger.debug('sign and send: {}'.format(spec))
        parent_conn, child_conn = multiprocessing.Pipe()
        p = multiprocessing.Process(
            target=sign_and_send,
            args=(self.tmpgpg, spec, child_conn)
        )
        p.start()
        gobject.timeout_add(200, self.on_check, parent_conn)

    def on_check(self, conn):
        while conn.poll():
            fraction, payload = conn.recv()
            if fraction is None:
                # status message
                logger.info('SIGNING COMPLETE')
                self.emit('sign-complete', payload)
            else:
                # progress message
                self.progress_bar.set_fraction(fraction)
                if not payload[0]:  # error
                    logger.error(repr(payload[1]))
                if fraction >= 1:
                    self.emit('send-complete')
                    return False
        return True

    def on_sign_complete(self, page, sigfile):
        logger.debug('GOT SIGFILE {}'.format(sigfile))
        self.notice.set_label(
            "Signatures have been written to {} ."
            .format(sigfile)
        )


class SummaryPage(gtk.VBox):
    def __init__(self, progress_page):
        super(SummaryPage, self).__init__()
        text = 'Signing and emailing completed.'
        self.pack_start(gtk.Label(text))

        self.import_help_label = gtk.Label()
        self.import_help_label.set_line_wrap(True)
        self.import_help_label.set_selectable(True)
        self.pack_start(self.import_help_label)

        progress_page.connect('sign-complete', self.on_sign_complete)

    def on_sign_complete(self, page, sigfile):
        msg = (
            'Signatures have been written to <tt>{0}</tt>.  You can import '
            'them into your keyring by issuing the following command at a '
            'terminal:\n'
            '\n'
            '<tt>gpg --import &lt; {0}</tt>'
        ).format(sigfile)
        self.import_help_label.set_markup(msg)

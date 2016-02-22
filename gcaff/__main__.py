# This file is part of gcaff
# Copyright (C) 2013, 2015  Fraser Tweedale
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

import argparse
import logging
import os
import shutil
import socket
import tempfile
import sys

import gi
gi.require_version('Gtk', '3.0')
import gi.repository.Gtk as gtk

from . import gpg
from . import mail
from . import ui
from . import version


def run_assistant():
    homegpg = gpg.GnuPG()

    tmpgpgdir = tempfile.mkdtemp()
    tmpgpg = gpg.GnuPG(tmpgpgdir)

    # link temporary homedir to existing agent
    agent_socket = homegpg.agent_socket()
    if agent_socket:
        os.symlink(agent_socket, os.path.join(tmpgpgdir, 'S.gpg-agent'))

    window = ui.SigningAssistant(homegpg, tmpgpg)
    window.show_all()
    gtk.main()

    logging.warn('remove tmpgpgdir: {}'.format(tmpgpgdir))
    shutil.rmtree(tmpgpgdir)


def run_error(text, secondary_text):
    window = gtk.MessageDialog(
        type=gtk.MessageType.ERROR,
        buttons=gtk.ButtonsType.CLOSE
    )
    window.connect('response', gtk.main_quit)
    window.set_property('text', text)
    window.set_property('secondary-text', secondary_text)
    window.show_all()
    gtk.main()
    sys.exit()


def main():
    parser = argparse.ArgumentParser(
        description="Graphical OpenPGP key signing assistant")
    parser.add_argument(
        '--version', action='version',
        version='%(prog)s ' + version.VERSION)
    parser.add_argument('--logging', default='WARNING', help='set log level')

    args = parser.parse_args()

    try:
        gpg.test_agent()
        mail.test_smtp()
    except gpg.AgentError as e:
        run_error('Could not connect to gpg-agent', e.args[0])
    except socket.error as e:
        run_error('Could not connect to local mailer', str(e))

    level = getattr(logging, args.logging.upper(), 'WARNING')
    logging.basicConfig(level=level)

    run_assistant()


if __name__ == '__main__':
    main()

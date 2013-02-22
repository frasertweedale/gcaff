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

import argparse
import logging
import shutil
import tempfile

import gtk

from . import gpg
from . import ui



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--keyring', type=argparse.FileType(), required=True,
        help='keyring containing keys to be signed')
    parser.add_argument('--logging', default='WARNING',
        help='set log level')

    args = parser.parse_args()

    level = getattr(logging, args.logging.upper(), 'WARNING')
    logging.basicConfig(level=level)

    homegpg = gpg.GnuPG()

    tmpgpgdir = tempfile.mkdtemp()
    tmpgpg = gpg.GnuPG(tmpgpgdir)
    tmpgpg.import_keys(args.keyring.read(), minimal=True)
    # TODO import chosen signing key into tmpgpg

    window = ui.SigningAssistant(homegpg, tmpgpg)
    window.show_all()
    gtk.main()

    logging.warn('remove tmpgpgdir: {}'.format(tmpgpgdir))
    shutil.rmtree(tmpgpgdir)

if __name__ == '__main__':
    main()

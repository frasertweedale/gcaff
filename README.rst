``gcaff`` - graphical OpenPGP signing assistant
===============================================

Synopsis
--------

::

    pip install gcaff
    gcaff --keyring keys-to-sign.asc


What is ``gcaff``?
------------------

``gcaff`` is a graphical tool for signing OpenPGP keys.  Its main
use case is for signing many keys at once, after a keysigning party
for example.


What are its features?
----------------------

Features include:

* display photo IDs and select for signing
* use multiple signing keys at once
* choose the certification level on a per-key basis
* email each signature separately, only to the associated email
  address


How does it differ from ``caff``?
---------------------------------

``gcaff`` is heavily influenced by caff_.  Apart from the
obvious, there are a few important differences from ``caff``.

* ``gcaff`` does not remove uids from keys.  ``caff`` sends only the
  uid that was signed to each email address.  For now, ``gcaff``
  does not do this, though it does send only the one new signature
  to each uid.
* ``gcaff`` sends photo uid or freefrom uid signatures to *all*
  email addresses on a key.  If a uid does not have an email
  address, this "scatter-gun" strategy is used so that the signature
  still has a chance of reaching the key owner.
* ``gcaff`` has no pinentry mechanism whatsoever.  You must have a
  working gpg-agent to use ``gcaff``.
* ``gcaff`` currently requires the user to supply a file containing
  keys to be signed; the program does not fetch any keys itself.

.. _caff: http://pgp-tools.alioth.debian.org/


Cryptographic concerns
----------------------

``gcaff`` currently signs keys using the SHA256 digest.  Future work
may allow users to choose a digest based on the capabilities of
their GnuPG implementation.

**Under no circumstances** are any secret keys exported from the
user's GnuPG home directory.  The corresponding public keys are
exported to a temporary GnuPG keyring during the signing process.

No keys in the user's GnuPG home directory are modified during the
signing process.  Once signing is complete, all the signatures are
written to a file whose location is reported to the user, from where
they may - at the user's discretion - imported into the regular
keyring.


Dependencies
------------

* GnuPG (using gpg-agent)
* Python 2.7
* PyGTK >=2, <3
* a local mailer (SMTP), e.g. sendmail


License
-------

``gcaff`` is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.


Contributing
------------

Bug reports, general feedback, patches and translations are welcome.

To submit a patch, please use ``git send-email`` or generate a
pull/merge request.  Write a `well formed commit message`_.  If your
patch is nontrivial, add a copyright notice (or, if appropriate,
update an existing notice) at the top of each file added or changed.

.. _well formed commit message: http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html

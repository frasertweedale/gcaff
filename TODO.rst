Signing
-------

- Allow user to choose digest algo (from reasonable values).

- One-button import of signatures into primary keyring.

- Implement alternative ways to specify signing candidates (e.g.,
  supply keyids in command line args or GUI and import from
  keyserver)

- Better handling of case where no uids were selected to be signed.

- Cache selected uids for subsequent runs in the event of error
  during signing or mailing.

- Detect case where no uid with an email address has been selected.
  Possible handling:
  - Just warn that the signed uid(s) won't be emailed.
  - Force user to provide an email address to which to send.
  - Prohibit signing of this key.


Mailer
------

- When no local mailer installed, determine OS and provide
  instructions for installing/configuring one.

- Alternatively, implement support for detecting or asking for an
  alternative SMTP server.

- Allow user to choose the ``From`` address for sending keys from
  the uids on the signing key(s).


UI / UX
-------

- General UI / UX improvements

- "About" dialog

- i18n

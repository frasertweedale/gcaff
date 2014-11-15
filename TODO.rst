Signing
-------

- Allow user to choose digest algo (from reasonable values).

- One-button import of signatures into primary keyring.

- Implement alternative ways to specify signing candidates (e.g.,
  supply keyids in command line args or GUI and import from
  keyserver)


Mailer
------

- When no local mailer installed, determine OS and provide
  instructions for installing/configuring one.

- Alternatively, implement support for detecting or asking for an
  alternative SMTP server.

- Allow user to choose the ``From`` address for sending keys from
  the uids on the signing key(s).

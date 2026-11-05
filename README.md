honeypot-ftp-python3
============

Adapted from https://github.com/alexbredo/honeypot-ftp FTP Honeypot by Alexander Bredo.
Minor changes to allow for more lightweight logging, elasticsearch support and command line flags including a more verbose output.

Features:
 * FTP + SSL-FTP
 * Catch used credentials
 * Catch malware files
 * distribute honeytoken files

Dependencies:
 * Twisted
 * My site-packages(3) --> common-modules

Usage:
```bash
# Dependencies (Debian 12: apt install python3-twisted python3-openssl; python3-elasticsearch only for --log elasticsearch)
python3 ftp.py --help
# Plain FTP on 21 and implicit FTPS on 990, events as JSON lines on screen and in honeypot_output.txt
python3 ftp.py --log file
```

Options: `--port` (21), `--sslport` (990, 0 disables), `--sslkey`/`--sslcert` (the bundled key pair; generate your own),
`--log screen|file|elasticsearch`, `--logfile`, `--es-host`/`--es-port`/`--es-index`, `--bind`, `--pubdir` (pub/),
`--passwd` (passwd), `--allow-login`, `--passive-ports` (e.g. 30000-30009), `--banner`, `--verbose`.

Changes from the original (2026 update):
 * Runs on Python 3 with current Twisted (tested with Twisted 22.4 on Debian 12, Python 3.11); no site-packages3 needed.
 * Default ports are the original's again (21 and 990), and the FTPS listener runs whatever the log mode.
 * Events are written as one JSON object per line (screen, file or Elasticsearch); commands are logged as text.
 * The fake STOR, DELE, RNFR, RNTO, MKD and RMD replies send bytes, as Twisted on Python 3 requires.
 * The original hands its password checker to FTPFactory instead of the Portal, so no login ever succeeds and
   'anonymous' is treated as an ordinary account. That behaviour is kept as the default; `--allow-login` registers the
   passwd file as the author intended (logged-in users see pubdir read-only; writes are acknowledged but never done).
 * The elasticsearch module is imported only when `--log elasticsearch` is used.

Contribution welcome.

FAQ
===
1) Generate SSL-Certificates

CA:
openssl genrsa -out ca.private.key 4096
openssl req -new -x509 -days 4096 -key ca.private.key -out ca.public.key

SRV:
openssl genrsa -out smtp.private.key 4096
openssl req -new -key smtp.private.key -out smtp.csr
openssl x509 -req -days 1024 -in smtp.csr -CA ca.public.key -CAkey ca.private.key -set_serial 01 -out smtp.public.key

SSL Check Connection
openssl s_client -quiet -connect 127.0.0.1:990

2) Known Errors
OpenSSL.SSL.Error: [('system library', 'fopen', 'No such process'), ('BIO routines', 'FILE_CTRL', 'system lib'), ('SSL routines', 'SSL_CTX_use_certificate_file', 'system lib')]
 --> Certifcate Files not found (wrong path?)

All rights reserved.
(c) 2014 by Alexander Bredo, 2024 James Brine

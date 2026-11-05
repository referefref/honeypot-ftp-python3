#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Alexander Bredo, 2024 James Brine
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the 
# following conditions are met:
# 
# 1. Redistributions of source code must retain the above 
# copyright notice, this list of conditions and the following 
# disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above 
# copyright notice, this list of conditions and the following 
# disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.

"""FTP honeypot (Python 3 version of alexbredo/honeypot-ftp).

Every connection, command line and disconnection is recorded as one JSON event
(source and destination address and port, command, session id).

Default behaviour matches the original: plain FTP on port 21 and implicit FTPS
on port 990 with the certificate in keys/, Twisted's FTP replies, and no login
ever succeeds (the original passes its password checker to FTPFactory instead
of the Portal, so the passwd file is never consulted). --allow-login wires the
passwd file in as the author intended; logged-in users then see pubdir
read-only, and uploads, deletes, renames and new folders are acknowledged but
never carried out.
"""

import argparse, json, logging, os, sys, time, uuid
from twisted.python import filepath
from twisted.protocols.ftp import FTPFactory, FTPRealm, FTP
from twisted.cred.portal import Portal
from twisted.cred.checkers import FilePasswordDB
from twisted.cred.credentials import UsernamePassword
from twisted.internet import reactor, ssl

parser = argparse.ArgumentParser(description='FTP Honeypot')
parser.add_argument('--log', choices=['screen', 'file', 'elasticsearch'], default='screen',
                    help='where events go: screen (stderr), file (screen and --logfile) or elasticsearch (default: screen)')
parser.add_argument('--logfile', default='honeypot_output.txt', help='event file for --log file, one JSON object per line')
parser.add_argument('--es-host', default='127.0.0.1', help='Elasticsearch host for --log elasticsearch')
parser.add_argument('--es-port', type=int, default=9200, help='Elasticsearch port')
parser.add_argument('--es-index', default='honeypot', help='Elasticsearch index')
parser.add_argument('--bind', default='', help='address to listen on (default: all)')
parser.add_argument('--port', type=int, default=21, help='plain FTP port (default: 21)')
parser.add_argument('--sslport', type=int, default=990, help='implicit FTPS port, 0 to disable (default: 990)')
parser.add_argument('--sslkey', default='keys/smtp.private.key', help='TLS private key (default: the bundled key)')
parser.add_argument('--sslcert', default='keys/smtp.public.key', help='TLS certificate (default: the bundled certificate)')
parser.add_argument('--pubdir', default='pub/', help='directory shown to logged-in users')
parser.add_argument('--passwd', default='passwd', help='user:password file used with --allow-login')
parser.add_argument('--allow-login', action='store_true', help='accept the accounts in --passwd (the original never accepts a login)')
parser.add_argument('--passive-ports', default='', help='passive data port range, e.g. 30000-30009 (default: any free port)')
parser.add_argument('--banner', default='', help="greeting text after '220 ' (default: Twisted's 'Twisted <version> FTP Server')")
parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
args = parser.parse_args()

logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('honeypot_ftp')

es = None
event_file = None
if args.log == 'file':
    event_file = open(args.logfile, 'a', buffering=1, encoding='utf-8')
elif args.log == 'elasticsearch':
    from elasticsearch import Elasticsearch
    es = Elasticsearch(['http://%s:%d' % (args.es_host, args.es_port)])


def handle(data):
    line = json.dumps(data, ensure_ascii=False)
    logger.info('FTP Event: %s', line)
    if event_file:
        event_file.write(line + '\n')
    if es is not None:
        try:
            es.index(index=args.es_index, body=data)
        except Exception as e:
            logger.error('Elasticsearch: %s', e)


class PasswdFileChecker(FilePasswordDB):
    """FilePasswordDB compares bytes from the file with the text user name Twisted's FTP passes on Python 3."""
    def requestAvatarId(self, c):
        return FilePasswordDB.requestAvatarId(self, UsernamePassword(
            c.username.encode('utf-8') if isinstance(c.username, str) else c.username,
            c.password.encode('utf-8') if isinstance(c.password, str) else c.password))


class MyFTPRealm(FTPRealm):
    def __init__(self, dir):
        self.userHome = filepath.FilePath(dir)

    def getHomeDirectory(self, avatarId):
        return self.userHome  # Hack: ignore users' directories


class SimpleFtpProtocol(FTP):
    def __init__(self):
        super().__init__()
        self.session = str(uuid.uuid1())
        self.myownhost = None

    def connectionMade(self):
        self.__logInfo('connected', '', True)
        super().connectionMade()

    def connectionLost(self, reason):
        self.__logInfo('disconnected', '', True)
        super().connectionLost(reason)

    def lineReceived(self, line):
        self.__logInfo('command', line.decode('utf-8', 'replace') if isinstance(line, bytes) else line, True)
        return super().lineReceived(line)

    def _say(self, text):
        return self.sendLine(text.encode('utf-8'))

    # BEGIN HACKS: do not write anything to disk (remove functionality)

    def ftp_STOR(self, path):
        self._say('125 Data connection already open, starting transfer')
        self._say('226 Transfer Complete.')

    def ftp_DELE(self, path):
        self._say('250 Requested File Action Completed OK')

    def ftp_RNFR(self, fromName):
        self._say('350 Requested file action pending further information.')

    def ftp_RNTO(self, toName):
        self._say('250 Requested File Action Completed OK')

    def ftp_MKD(self, path):
        self._say('257 Folder created')

    def ftp_RMD(self, path):
        self._say('250 Requested File Action Completed OK')

    # END HACKS

    def __logInfo(self, type, command, successful):
        try:  # Hack: on connection close the socket is unavailable; remember the old address
            self.myownhost = self.transport.getHost()
        except AttributeError:
            pass
        peer = self.transport.getPeer()
        data = {
            'module': 'FTP',
            '@timestamp': int(time.time() * 1000),  # in milliseconds
            'sourceIPv4Address': str(peer.host),
            'sourceTransportPort': peer.port,
            'type': type,
            'command': command,
            'success': successful,
            'session': self.session
        }
        if self.myownhost:
            data['destinationIPv4Address'] = str(self.myownhost.host)
            data['destinationTransportPort'] = self.myownhost.port
        handle(data)


try:
    os.makedirs(args.pubdir, exist_ok=True)
    portal = Portal(MyFTPRealm(args.pubdir))
    if args.allow_login:
        portal.registerChecker(PasswdFileChecker(args.passwd))
    factory = FTPFactory(portal)
    # The original passes its checker list as FTPFactory's second argument (userAnonymous),
    # so 'anonymous' is treated as an ordinary account; kept for fidelity.
    factory.userAnonymous = [FilePasswordDB(args.passwd)]
    factory.protocol = SimpleFtpProtocol
    if args.banner:
        factory.welcomeMessage = args.banner
    if args.passive_ports:
        lo, hi = (int(x) for x in args.passive_ports.split('-'))
        factory.passivePortRange = range(lo, hi + 1)
    reactor.listenTCP(args.port, factory, interface=args.bind)
    if args.sslport:
        reactor.listenSSL(args.sslport, factory,
                          ssl.DefaultOpenSSLContextFactory(args.sslkey, args.sslcert),
                          interface=args.bind)
    logger.info('Server listening on Port %s (Plain) and on %s (SSL). Logins %s.', args.port,
                args.sslport or 'none', 'accepted from %s' % args.passwd if args.allow_login else 'never accepted')
    reactor.run()
except Exception as e:
    logger.error(str(e))
    sys.exit(-1)

logger.info('Server shutdown.')

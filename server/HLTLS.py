""" TLS support for phxd's listeners (used for IRC over TLS).

``ReloadingTLSContextFactory`` serves a PEM certificate chain and private
key, and reloads them when the files change, so a renewed certificate
(e.g. from Let's Encrypt) is picked up without restarting the server and
disconnecting everyone. Twisted asks the factory for a context for every
new connection; the files are only re-read when their modification time
changes.
"""
from __future__ import absolute_import

import os

from OpenSSL import SSL
from twisted.internet.interfaces import IOpenSSLServerConnectionCreator
from zope.interface import implementer


class TLSConfigError( Exception ):
    pass


def buildServerContext( certPath , keyPath ):
    """ Returns an OpenSSL server context for the given PEM files,
    accepting TLS 1.2 and newer only. Raises TLSConfigError if the files
    are missing, invalid or don't match. """
    try:
        context = SSL.Context( SSL.TLS_SERVER_METHOD )
        context.set_min_proto_version( SSL.TLS1_2_VERSION )
        context.set_options( SSL.OP_NO_COMPRESSION | SSL.OP_CIPHER_SERVER_PREFERENCE )
        context.use_certificate_chain_file( certPath )
        context.use_privatekey_file( keyPath )
        context.check_privatekey()
    except ( SSL.Error , OSError ) as e:
        raise TLSConfigError( "cannot load TLS certificate %r / key %r: %s" % ( certPath , keyPath , e ) )
    return context


@implementer( IOpenSSLServerConnectionCreator )
class ReloadingTLSContextFactory:
    """ A Twisted TLS connection creator that reloads its certificate and
    key when the files change. If a reload fails (e.g. a half-written
    renewal), the previous certificate keeps being used. """

    def __init__( self , certPath , keyPath , log = None ):
        self.certPath = certPath
        self.keyPath = keyPath
        self.log = log
        self._context = None
        self._stamp = None
        # Stamp of files that failed to load, so a broken renewal is
        # logged once instead of on every connection.
        self._failedStamp = None
        # Load now so a bad configuration fails at startup, not on the
        # first connection.
        self.getContext()

    def _fileStamp( self ):
        # os.stat follows symlinks, so a Let's Encrypt "live/" symlink
        # switching to a new archive file is noticed too.
        stamps = []
        for path in ( self.certPath , self.keyPath ):
            st = os.stat( path )
            stamps.append( ( os.path.realpath( path ) , st.st_mtime_ns , st.st_size ) )
        return tuple( stamps )

    def getContext( self ):
        try:
            stamp = self._fileStamp()
        except OSError as e:
            if self._context is None:
                raise TLSConfigError( "cannot read TLS certificate %r / key %r: %s" % ( self.certPath , self.keyPath , e ) )
            self._warn( "TLS certificate files unreadable (%s), keeping the current certificate" , e )
            return self._context
        if stamp != self._stamp and stamp != self._failedStamp:
            try:
                context = buildServerContext( self.certPath , self.keyPath )
            except TLSConfigError as e:
                if self._context is None:
                    raise
                self._failedStamp = stamp
                self._warn( "%s; keeping the current certificate" , e )
                return self._context
            reloaded = self._context is not None
            self._context = context
            self._stamp = stamp
            if reloaded and self.log is not None:
                self.log.info( "Reloaded TLS certificate %s" , self.certPath )
        return self._context

    def serverConnectionForTLS( self , tlsProtocol ):
        """ IOpenSSLServerConnectionCreator: called by Twisted for every
        new TLS connection. """
        return SSL.Connection( self.getContext() , None )

    def _warn( self , msg , *args ):
        if self.log is not None:
            self.log.error( msg , *args )

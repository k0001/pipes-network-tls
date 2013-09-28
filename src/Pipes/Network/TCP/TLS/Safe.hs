{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE TypeFamilies #-}

-- | This module exports facilities allowing you to safely obtain, use and
-- release TLS-secured TCP connections within a /Pipes/ pipeline, by relying on
-- @pipes-safe@.
--
-- This module is meant to be used together with "Pipes.Network.TCP.TLS", and it
-- overrides some functions from "Network.Simple.TCP" so that they support
-- 'P.MonadSafe'. Additionally, it also exports pipes that establish a
-- TLS-secured TCP connection and interact with it unidirectionally, in a
-- streaming fashion at once.
--
-- You are encouraged to use this module together with "Pipes.Network.TCP.TLS"
-- and "Network.Simple.TCP.TLS" as follows:
--
-- @
-- import qualified "Network.Simple.TCP.TLS"     as TLS hiding (connect, serve, listen, accept)
-- import qualified "Pipes.Network.TCP.TLS"      as TLS
-- import qualified "Pipes.Network.TCP.TLS.Safe" as TLS
-- @

module Pipes.Network.TCP.TLS.Safe (
  -- * @MonadSafe@-compatible upgrades
  -- $network-simple-upgrades
    connect
  , serve
  , listen
  , accept
  -- * Streaming
  -- ** Client side
  -- $client-streaming
  , fromConnect
  , toConnect
  -- ** Server side
  -- $server-streaming
  , fromServe
  , toServe
  ) where


import           Control.Monad                   (forever)
import           Pipes
import qualified Pipes.Safe                      as P
import           Data.ByteString                 (ByteString)
import qualified Network.Simple.TCP.TLS          as S
import           Pipes.Network.TCP.Safe          (listen)
import           Pipes.Network.TCP.TLS           (fromContext, toContext)
import           Network.TLS                     (contextClose)

--------------------------------------------------------------------------------

-- $network-simple-upgrades
--
-- The following functions are analogous versions of those exported by
-- "Network.Simple.TCP.TLS", but compatible with 'P.MonadSafe'.

-- | Like 'Network.Simple.TCP.TLS.connect' from "Network.Simple.TCP.TLS", but
-- compatible with 'P.MonadSafe'.
connect
  :: (P.MonadSafe m, P.Base m ~ IO)
  => S.ClientSettings -> S.HostName -> S.ServiceName
  -> ((S.Context, S.SockAddr) -> m r) -> m r
connect cs host port k = P.bracket (S.connectTls cs host port)
                                   (liftIO . contextClose . fst)
                                   (S.useTls k)

-- | Like 'Network.Simple.TCP.TLS.serve' from "Network.Simple.TCP.TLS", but
-- compatible with 'P.MonadSafe'.
serve
  :: (P.MonadSafe m, P.Base m ~ IO)
  => S.ServerSettings -> S.HostPreference -> S.ServiceName
  -> ((S.Context, S.SockAddr) -> IO ()) -> m r
serve ss hp port k = do
   listen hp port $ \(lsock,_) -> do
      forever $ S.acceptFork ss lsock k

-- | Like 'Network.Simple.TCP.TLS.accept' from "Network.Simple.TCP.TLS", but
-- compatible with 'P.MonadSafe'.
accept
  :: (P.MonadSafe m, P.Base m ~ IO)
  => S.ServerSettings -> S.Socket -> ((S.Context, S.SockAddr) -> m r) -> m r
accept ss lsock k = P.bracket (S.acceptTls ss lsock)
                              (liftIO . contextClose . fst)
                              (S.useTls k)
{-# INLINABLE accept #-}

--------------------------------------------------------------------------------

-- $client-streaming
--
-- The following proxies allow you to easily connect to a TLS-secured TCP server
-- and immediately interact with it in a streaming fashion, all at once, instead
-- of having to perform the individual steps separately.

--------------------------------------------------------------------------------

-- | Connect to a TLS-secured TCP server and send downstream the decrypted bytes
-- received from the remote end.
--
-- Up to @16384@ decrypted bytes will be received at once. The TLS connection is
-- automatically renegotiated if a /ClientHello/ message is received.
--
-- If the remote peer closes its side of the connection of EOF is reached, this
-- proxy returns.
--
-- The connection is closed when done or in case of exceptions.
fromConnect
  :: (P.MonadSafe m, P.Base m ~ IO)
  => S.ClientSettings   -- ^TLS settings.
  -> S.HostName
  -> S.ServiceName      -- ^Server service port.
  -> Producer' ByteString m ()
fromConnect cs host port = do
   connect cs host port $ \(ctx,_) -> do
     fromContext ctx

-- | Connects to a TLS-secured TCP server, then repeatedly encrypts and sends to
-- the remote end the bytes received from upstream.
--
-- The connection is properly closed when done or in case of exceptions.
toConnect
  :: (P.MonadSafe m, P.Base m ~ IO)
  => S.ClientSettings   -- ^TLS settings.
  -> S.HostName         -- ^Server host name.
  -> S.ServiceName      -- ^Server service port.
  -> Consumer' ByteString m ()
toConnect cs hp port = do
   connect cs hp port $ \(ctx,_) ->
     toContext ctx

--------------------------------------------------------------------------------

-- $server-streaming
--
-- The following proxies allow you to easily run a TLS-secured TCP server and
-- immediately interact with incoming connections in a streaming fashion, all at
-- once, instead of having to perform the individual steps separately.

--------------------------------------------------------------------------------

-- | Binds a listening TCP socket, accepts a single TLS-secured connection and
-- sends downstream any decrypted bytes received from the remote end.
--
-- Up to @16384@ decrypted bytes will be received at once. The TLS connection is
-- automatically renegotiated if a /ClientHello/ message is received.
--
-- If the remote peer closes its side of the connection of EOF is reached,  this
-- proxy returns.
--
-- Both the listening and connection sockets are closed when done or in case of
-- exceptions.
fromServe
  :: (P.MonadSafe m, P.Base m ~ IO)
  => S.ServerSettings   -- ^TLS settings.
  -> S.HostPreference   -- ^Preferred host to bind.
  -> S.ServiceName      -- ^Service port to bind.
  -> Producer' ByteString m ()
fromServe ss hp port = do
   listen hp port $ \(lsock,_) -> do
     accept ss lsock $ \(ctx,_) -> do
       fromContext ctx

-- | Binds a listening TCP socket, accepts a single TLS-secured connection,
-- and repeatedly sends to the remote end any bytes received from upstream.
--
-- If the remote peer closes its side of the connection, this proxy returns.
--
-- Both the listening and connection sockets are closed when done or in case of
-- exceptions.
toServe
  :: (P.MonadSafe m, P.Base m ~ IO)
  => S.ServerSettings   -- ^TLS settings.
  -> S.HostPreference   -- ^Preferred host to bind.
  -> S.ServiceName      -- ^Service port to bind.
  -> Consumer' ByteString m r
toServe ss hp port = do
   listen hp port $ \(lsock,_) -> do
     accept ss lsock $ \(ctx,_) -> do
       toContext ctx


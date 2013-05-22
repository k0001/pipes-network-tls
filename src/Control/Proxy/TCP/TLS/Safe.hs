{-# LANGUAGE Rank2Types #-}

-- | This module exports functions that allow you to use TLS-secured
-- TCP connections as 'P.Proxy' streams, as well as utilities to connect to a
-- TLS-enabled TCP server or running your own, possibly within the pipeline
-- itself by relying on the facilities provided by 'P.ExceptionP' from the
-- @pipes-safe@ library.
--
-- Instead, if just want to use resources already acquired or released outside
-- the pipeline, then you could use the simpler and similar functions exported
-- by "Control.Proxy.TCP.TLS".

module Control.Proxy.TCP.TLS.Safe (
  -- * Client side
  -- $client-side
    connect
  -- ** Streaming
  -- $client-streaming
  , connectReadS
  , connectWriteD

  -- * Server side
  -- $server-side
  , serve
  -- ** Listening
  , listen
  -- ** Accepting
  , accept
  , acceptFork
  -- ** Streaming
  -- $server-streaming
  , serveReadS
  , serveWriteD

  -- * Socket streams
  -- $socket-streaming
  , tlsReadS
  , tlsWriteD

  -- * Exports
  , S.HostPreference(..)
  , S.Credential(..)
  , S.ServerSettings
  , S.makeServerSettings
  , S.ClientSettings
  , S.makeClientSettings
  , S.getDefaultClientSettings
  , Timeout(..)
  ) where


import           Control.Concurrent              (ThreadId)
import qualified Control.Exception               as E
import           Control.Monad
import qualified Control.Proxy                   as P
import qualified Control.Proxy.Safe              as P
import           Control.Proxy.TCP.Safe          (listen, Timeout(..))
import qualified Data.ByteString                 as B
import           Data.Monoid
import qualified Network.Socket                  as NS
import qualified Network.Simple.TCP.TLS          as S
import qualified Network.TLS                     as T
import           System.Timeout                  (timeout)

--------------------------------------------------------------------------------

-- $client-side
--
-- Here's how you could run a simple TLS-secured TCP client:
--
-- > import Control.Proxy.TCP.TLS.Safe
-- >
-- > settings <- getDefaultClientSettings
-- > connect settings "www.example.org" "443" $ \(tlsCtx, remoteAddr) -> do
-- >   tryIO . putStrLn $ "Secure connection established to " ++ show remoteAddr
-- >   -- now you may use tlsCtx as you please within this scope, possibly with
-- >   -- the tlsReadS, ntlsReadS or tlsWriteD proxies explained below.
--
-- You might prefer to use the simpler but less general solutions offered by
-- 'connectReadS' and 'connectWriteD', so check those too.

--------------------------------------------------------------------------------

-- | Connect to a TLS-secured TCP server and use the connection.
--
-- The connection is closed when done or in case of exceptions.
--
-- If you prefer to open and close the connection yourself, then use
-- 'S.connectTls' instead"
connect
  :: (P.Proxy p, Monad m)
  => (forall x. P.SafeIO x -> m x) -- ^Monad morphism.
  -> S.ClientSettings              -- ^TLS settings.
  -> NS.HostName                   -- ^Server hostname.
  -> NS.ServiceName                -- ^Server service port.
  -> ((T.Context, NS.SockAddr) -> P.ExceptionP p a' a b' b m r)
                          -- ^Computation to run in a different thread
                          -- once a TLS-secured connection is established. Takes
                          -- the TLS connection context and remote end address.
  -> P.ExceptionP p a' a b' b m r
connect morph cs h p k = do
    conn <- P.hoist morph . P.tryIO $ S.connectTls cs h p
    useTls morph k conn

--------------------------------------------------------------------------------

-- $client-streaming
--
-- The following proxies allow you to easily connect to a TLS-secured TCP server
-- and immediately interact with it using streams, all at once, instead of
-- having to perform the individual steps separately.

--------------------------------------------------------------------------------

-- | Connect to a TLS-secured TCP server and send downstream the decrypted bytes
-- received from the remote end.
--
-- Up to @16384@ decrypted bytes will be received at once. The TLS connection is
-- automatically renegotiated if a /ClientHello/ message is received.
--
-- If an optional timeout is given and receiveing data from the remote end takes
-- more time that such timeout, then throw a 'Timeout' exception in the
-- 'P.ExceptionP' proxy transformer.
--
-- If the remote peer closes its side of the connection of EOF is reached,  this
-- proxy returns.
--
-- The connection is closed when done or in case of exceptions.
--
-- Using this proxy you can write code like the following, which prints whatever
-- is received through a TLS-secured TCP connection to a given server listening
-- at hostname "example.org" on port 4433:
--
-- >>> settings <- getDefaultClientSettings
-- >>> let src = connectReadS Nothing settings "www.example.org" "4433"
-- >>> runSafeIO . runProxy . runEitherK $ src >-> tryK printD
connectReadS
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> S.ClientSettings   -- ^TLS settings.
  -> NS.HostName
  -> NS.ServiceName     -- ^Server service port.
  -> () -> P.Producer (P.ExceptionP p) B.ByteString P.SafeIO ()
connectReadS mwait cs host port () = do
   connect id cs host port $ \(ctx,_) -> do
     tlsReadS mwait ctx ()

-- | Connects to a TLS-secured TCP server, encrypts and sends to the remote end
-- the bytes received from upstream, then forwards such same bytes downstream.
--
-- Requests from downstream are forwarded upstream.
--
-- If an optional timeout is given and sending data to the remote end takes
-- more time that such timeout, then throw a 'Timeout' exception in the
-- 'P.ExceptionP' proxy transformer.
--
-- If the remote peer closes its side of the connection, this proxy returns.
--
-- The connection is closed when done or in case of exceptions.
--
-- Using this proxy you can write code like the following, which sends data to a
-- TLS-secured TCP server listening at hostname "example.org" on port 4433:
--
-- >>> :set -XOverloadedStrings
-- >>> settings <- getDefaultClientSettings
-- >>> let dst = connectWriteS Nothing settings "www.example.org" "4433"
-- >>> runSafeIO . runProxy . runEitherK $ fromListS ["He","llo\r\n"] >-> dst
connectWriteD
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> S.ClientSettings   -- ^TLS settings.
  -> NS.HostName        -- ^Server host name.
  -> NS.ServiceName     -- ^Server service port.
  -> x -> (P.ExceptionP p) x B.ByteString x B.ByteString P.SafeIO r
connectWriteD mwait cs hp port x = do
   connect id cs hp port $ \(ctx,_) ->
     tlsWriteD mwait ctx x

--------------------------------------------------------------------------------

-- $server-side
--
-- Here's how you could run a simple TLS-secured TCP server that handles in
-- different threads each incoming connection to port @4433@ at hostname
-- @example.org@. You will need a X509 certificate and a private key appropiate
-- to be used at that hostname.
--
-- > import Control.Proxy.TCP.TLS.Safe
-- > import Network.TLS.Extra (fileReadCertificate, fileReadPrivateKey)
-- >
-- > cert <- fileReadCertificate "~/example.org.crt"
-- > pkey <- fileReadPrivateKey  "~/example.org.key"
-- > let settings = makeServerSettings cert pkey Nothing
-- > serve settings (Host "example.org") "4433" $ \(tlsCtx, remoteAddr) -> do
-- >   tryIO . putStrLn $ "Secure connection established from " ++ show remoteAddr
-- >   -- now you may use tlsCtx as you please within this scope, possibly with
-- >   -- the tlsReadS, ntlsReadS or tlsWriteD proxies explained below.
--
-- You might prefer to use the simpler but less general solutions offered by
-- 'serveReadS' and 'serveWriteD', or if you need to control the way your
-- server runs, then you can use more advanced functions such as 'listen',
-- 'accept' and 'acceptFork', so check those functions too.

--------------------------------------------------------------------------------

-- | Start a TLS-secured TCP server that accepts incoming connections and
-- handles each of them concurrently, in different threads.
--
-- Any acquired network resources are properly closed and discarded when done or
-- in case of exceptions.
--
-- Note: This function binds a listening socket, accepts an connection, performs
-- a TLS handshake and then safely closes the connection. You don't need to
-- perform any of those steps manually.
serve
  :: (P.Proxy p, Monad m)
  => (forall x. P.SafeIO x -> m x) -- ^Monad morphism.
  -> S.ServerSettings              -- ^TLS settings.
  -> S.HostPreference              -- ^Preferred host to bind.
  -> NS.ServiceName                -- ^Service port to bind.
  -> ((T.Context, NS.SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> P.ExceptionP p a' a b' b m r
serve morph ss hp port k = do
   listen morph hp port $ \(lsock,_) -> do
     forever $ acceptFork morph ss lsock k

--------------------------------------------------------------------------------

-- | Accept a single incoming TLS-secured TCP connection and use it.
--
-- The connection is closed when done or in case of exceptions.
accept
  :: (P.Proxy p, Monad m)
  => (forall x. P.SafeIO x -> m x) -- ^Monad morphism.
  -> S.ServerSettings              -- ^TLS settings.
  -> NS.Socket                     -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> P.ExceptionP p a' a b' b m r)
                          -- ^Computation to run once an incomming connection is
                          -- accepted and a TLS-secured communication is
                          -- established. Takes the TLS connection context and
                          -- remote end address.
  -> P.ExceptionP p a' a b' b m r
accept morph ss lsock k = do
    conn <- P.hoist morph . P.tryIO $ S.acceptTls ss lsock
    useTls morph k conn
{-# INLINABLE accept #-}

-- | Accept a single incoming TLS-secured TCP connection and use it in a
-- different thread.
--
-- The connection is closed when done or in case of exceptions.
acceptFork
  :: (P.Proxy p, Monad m)
  => (forall x. P.SafeIO x -> m x) -- ^Monad morphism.
  -> S.ServerSettings              -- ^TLS settings.
  -> NS.Socket                     -- ^Listening and bound socket.
  -> ((T.Context, NS.SockAddr) -> IO ())
                          -- ^Computation to run in a different thread
                          -- once an incomming connection is accepted and a
                          -- TLS-secured communication is established. Takes the
                          -- TLS connection context and remote end address.
  -> P.ExceptionP p a' a b' b m ThreadId
acceptFork morph ss lsock k = P.hoist morph . P.tryIO $ S.acceptFork ss lsock k
{-# INLINABLE acceptFork #-}

--------------------------------------------------------------------------------

-- $server-streaming
--
-- The following proxies allow you to easily run a TLS-secured TCP server and
-- immediately interact with incoming connections using streams, all at once,
-- instead of having to perform the individual steps separately.

--------------------------------------------------------------------------------

-- | Binds a listening TCP socket, accepts a single TLS-secured connection and
-- sends downstream any decrypted bytes received from the remote end.
--
-- Up to @16384@ decrypted bytes will be received at once. The TLS connection is
-- automatically renegotiated if a /ClientHello/ message is received.
--
-- If an optional timeout is given and receiveing data from the remote end takes
-- more time that such timeout, then throw a 'Timeout' exception in the
-- 'P.ExceptionP' proxy transformer.
--
-- Less than the specified maximum number of bytes might be received at once.
--
-- If the remote peer closes its side of the connection of EOF is reached,  this
-- proxy returns.
--
-- Both the listening and connection sockets are closed when done or in case of
-- exceptions.
--
-- Using this proxy you can write code like the following, which prints data
-- received from a TLS-secured TCP connection to the hostname "example.org" at
-- port 4433:
--
-- >>> import Network.TLS.Extra (fileReadCertificate, fileReadPrivateKey)
-- >>> cert <- fileReadCertificate "~/example.org.crt"
-- >>> pkey <- fileReadPrivateKey  "~/example.org.key"
-- >>> let settings = makeServerSettings cert pkey Nothing
-- >>> let src = serveReadS Nothing settings (Host "example.org") "4433"
-- >>> runSafeIO . runProxy . runEitherK $ src >-> tryK printD
serveReadS
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> S.ServerSettings   -- ^TLS settings.
  -> S.HostPreference   -- ^Preferred host to bind.
  -> NS.ServiceName     -- ^Service port to bind.
  -> () -> P.Producer (P.ExceptionP p) B.ByteString P.SafeIO ()
serveReadS mwait ss hp port () = do
   listen id hp port $ \(lsock,_) -> do
     accept id ss lsock $ \(csock,_) -> do
       tlsReadS mwait csock ()

-- | Binds a listening TCP socket, accepts a single TLS-secured connection,
-- sends to the remote end the bytes received from upstream and then forwards
-- such sames bytesdownstream.
--
-- Requests from downstream are forwarded upstream.
--
-- If an optional timeout is given and sending data to the remote end takes
-- more time that such timeout, then throw a 'Timeout' exception in the
-- 'P.ExceptionP' proxy transformer.
--
-- If the remote peer closes its side of the connection, this proxy returns.
--
-- Both the listening and connection sockets are closed when done or in case of
-- exceptions.
--
-- Using this proxy you can write straightforward code like the following, which
-- sends data to an incoming TLS-secured TCP connection to the hostname
-- "example.org" at port 4433:
--
-- >>> :set -XOverloadedStrings
-- >>> import Network.TLS.Extra (fileReadCertificate, fileReadPrivateKey)
-- >>> cert <- fileReadCertificate "~/example.org.crt"
-- >>> pkey <- fileReadPrivateKey  "~/example.org.key"
-- >>> let settings = makeServerSettings cert pkey Nothing
-- >>> let dst = serveWriteD Nothing settings (Host "example.org") "4433"
-- >>> runSafeIO . runProxy . runEitherK $ fromListS ["He","llo\r\n"] >-> dst
serveWriteD
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> S.ServerSettings   -- ^TLS settings.
  -> S.HostPreference   -- ^Preferred host to bind.
  -> NS.ServiceName     -- ^Service port to bind.
  -> x -> (P.ExceptionP p) x B.ByteString x B.ByteString P.SafeIO r
serveWriteD mwait ss hp port x = do
   listen id hp port $ \(lsock,_) -> do
     accept id ss lsock $ \(csock,_) -> do
       tlsWriteD mwait csock x

--------------------------------------------------------------------------------

-- $socket-streaming
--
-- Once you have a an established TLS 'T.Context', you can use the following
-- 'P.Proxy's to interact with the other connection end using pipes streams.

--------------------------------------------------------------------------------

-- | Receives bytes from the remote end and sends them downstream.
--
-- If an optional timeout is given and receiveing data from the remote end takes
-- more time that such timeout, then throw a 'Timeout' exception in the
-- 'P.ExceptionP' proxy transformer.
--
-- Less than the specified maximum number of bytes might be received at once.
--
-- If the remote peer closes its side of the connection, this proxy returns.
tlsReadS
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> T.Context          -- ^Established TLS connection context.
  -> () -> P.Producer (P.ExceptionP p) B.ByteString P.SafeIO ()
tlsReadS Nothing ctx () = loop where
    loop = do
      mbs <- P.tryIO (S.recv ctx)
      case mbs of
        Nothing -> return ()
        Just bs -> P.respond bs >> loop
tlsReadS (Just wait) ctx () = loop where
    loop = do
      mmbs <- P.tryIO (timeout wait (S.recv ctx))
      case mmbs of
        Nothing        -> P.throw ex
        Just Nothing   -> return ()
        Just (Just bs) -> P.respond bs >> loop
    ex = Timeout $ "tlsReadS: " <> show wait <> " microseconds."
{-# INLINABLE tlsReadS #-}

-- | Sends to the remote end the bytes received from upstream, then forwards
-- such same bytes downstream.
--
-- If an optional timeout is given and sending data to the remote end takes
-- more time that such timeout, then throw a 'Timeout' exception in the
-- 'P.ExceptionP' proxy transformer.
--
-- If the remote peer closes its side of the connection, this proxy returns.
--
-- Requests from downstream are forwarded upstream.
tlsWriteD
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> T.Context          -- ^Established TLS connection context.
  -> x -> (P.ExceptionP p) x B.ByteString x B.ByteString P.SafeIO r
tlsWriteD Nothing ctx = loop where
    loop x = do
      a <- P.request x
      P.tryIO (S.send ctx a)
      P.respond a >>= loop
tlsWriteD (Just wait) ctx = loop where
    loop x = do
      a <- P.request x
      m <- P.tryIO (timeout wait (S.send ctx a))
      case m of
        Just () -> P.respond a >>= loop
        Nothing -> P.throw ex
    ex = Timeout $ "tlsWriteD: " <> show wait <> " microseconds."
{-# INLINABLE tlsWriteD #-}



--------------------------------------------------------------------------------
-- Internal stuff


-- | Perform a TLS 'T.handshake' on the given 'T.Context', then perform the
-- given action, and at last say 'T.bye' and close the TLS connection, even in
-- case of exceptions. Like 'S.useTls', except it runs within 'P.ExceptionP'.
useTls
  :: (Monad m, P.Proxy p)
  => (forall x. P.SafeIO x -> m x) -- ^Monad morphism.
  -> ((T.Context, NS.SockAddr) -> P.ExceptionP p a' a b' b m r)
  -> (T.Context, NS.SockAddr) -> P.ExceptionP p a' a b' b m r
useTls morph k conn@(ctx,_) =
    P.finally morph
       (discardExceptions (T.contextClose ctx))
       (do P.hoist morph (P.tryIO (T.handshake ctx))
           P.finally morph (discardExceptions (T.bye ctx)) (k conn))

-- | Dangerous thing: perform the given action ignoring all exceptions.
discardExceptions :: IO () -> IO ()
discardExceptions = E.handle (\e -> let _ = e :: E.SomeException in return ())


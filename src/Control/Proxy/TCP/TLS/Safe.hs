{-# LANGUAGE Rank2Types #-}

-- | This module exports functions that allow you to use TLS-secured
-- TCP connections as 'P.Proxy' streams, as well as utilities to connect to a
-- TLS-enabled TCP server or running your own, possibly within the pipeline
-- itself by relying on the facilities provided by 'P.ExceptionP' from the
-- @pipes-safe@ library.
--
-- If you don't need to establish new TLS connections within your pipeline,
-- then consider using the simpler and similar functions exported by
-- "Control.Proxy.TCP.TLS".
--
-- This module re-exports many functions and types from "Network.Simple.TCP.TLS"
-- module in the @network-simple@ package. You might refer to that module for
-- more documentation.

module Control.Proxy.TCP.TLS.Safe (
  -- * Client side
  -- $client-side
    connect
  , S.ClientSettings
  , S.getDefaultClientSettings
  , S.makeClientSettings
  -- ** Streaming
  -- $client-streaming
  , connectReadS
  , connectWriteD

  -- * Server side
  -- $server-side
  , serve
  , S.ServerSettings
  , S.makeServerSettings
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
  , contextReadS
  , contextWriteD

  -- * Note to Windows users
  -- $windows-users
  , NS.withSocketsDo

  -- * Exports
  , S.HostPreference(..)
  , S.Credential(..)
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
import qualified GHC.IO.Exception                as Eg
import qualified Network.Socket                  as NS
import qualified Network.Simple.TCP.TLS          as S
import qualified Network.TLS                     as T
import           System.Timeout                  (timeout)

--------------------------------------------------------------------------------

-- $windows-users
--
-- If you are running Windows, then you /must/ call 'NS.withSocketsDo', just
-- once, right at the beginning of your program. That is, change your program's
-- 'main' function from:
--
-- @
-- main = do
--   print \"Hello world\"
--   -- rest of the program...
-- @
--
-- To:
--
-- @
-- main = 'NS.withSocketsDo' $ do
--   print \"Hello world\"
--   -- rest of the program...
-- @
--
-- If you don't do this, your networking code won't work and you will get many
-- unexpected errors at runtime. If you use an operating system other than
-- Windows then you don't need to do this, but it is harmless to do it, so it's
-- recommended that you do for portability reasons.

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
-- >   -- the contextReadS or contextWriteD proxies explained below.
--
-- You might prefer to use the simpler but less general solutions offered by
-- 'connectReadS' and 'connectWriteD', so check those too.

--------------------------------------------------------------------------------

-- | Connect to a TLS-secured TCP server and use the connection.
--
-- A TLS handshake is performed immediately after establishing the TCP
-- connection.
--
-- The connection is properly closed when done or in case of exceptions. If you
-- need to manage the lifetime of the connection resources yourself, then use
-- 'connectTls' instead.
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
connect morph cs host port  k = do
    P.bracket morph (S.connectTls cs host port)
                    (contextCloseNoVanish . fst)
                    (useTls morph k)

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
-- If the remote peer closes its side of the connection of EOF is reached, this
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
-- >>> runSafeIO . runProxy . runEitherK $ src >-> try . printD
connectReadS
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> S.ClientSettings   -- ^TLS settings.
  -> NS.HostName
  -> NS.ServiceName     -- ^Server service port.
  -> () -> P.Producer (P.ExceptionP p) B.ByteString P.SafeIO ()
connectReadS mwait cs host port = \() -> do
   connect id cs host port $ \(ctx,_) -> do
     contextReadS mwait ctx ()

-- | Connects to a TLS-secured TCP server, encrypts and sends to the remote end
-- the bytes received from upstream, then forwards such same bytes downstream.
--
-- Requests from downstream are forwarded upstream.
--
-- If an optional timeout is given and sending data to the remote end takes
-- more time that such timeout, then throw a 'Timeout' exception in the
-- 'P.ExceptionP' proxy transformer.
--
-- The connection is properly closed when done or in case of exceptions.
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
connectWriteD mwait cs hp port = \x -> do
   connect id cs hp port $ \(ctx,_) ->
     contextWriteD mwait ctx x

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
-- > let cred = Credential cert pkey []
-- >     settings = makeServerSettings cred Nothing
-- >
-- > serve settings (Host "example.org") "4433" $ \(tlsCtx, remoteAddr) -> do
-- >   tryIO . putStrLn $ "Secure connection established from " ++ show remoteAddr
-- >   -- now you may use tlsCtx as you please within this scope, possibly with
-- >   -- the contextReadS or contextWriteD proxies explained below.
--
-- You might prefer to use the simpler but less general solutions offered by
-- 'serveReadS' and 'serveWriteD', or if you need to control the way your
-- server runs, then you can use more advanced functions such as 'listen',
-- 'accept' and 'acceptFork', so check those functions too.

--------------------------------------------------------------------------------

-- | Start a TLS-secured TCP server that accepts incoming connections and
-- handles each of them concurrently, in different threads.
--
-- A TLS handshake is performed immediately after establishing each TCP
-- connection.
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
-- A TLS handshake is performed immediately after establishing each TCP
-- connection.
--
-- The connection properly closed when done or in case of exceptions.
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
    P.bracket morph (S.acceptTls ss lsock)
                    (contextCloseNoVanish . fst)
                    (useTls morph k)
{-# INLINABLE accept #-}

-- | Like 'accept', except it uses a different thread to performs the TLS
-- handshake and run the given computation.
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
-- >>> runSafeIO . runProxy . runEitherK $ src >-> try . printD
serveReadS
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> S.ServerSettings   -- ^TLS settings.
  -> S.HostPreference   -- ^Preferred host to bind.
  -> NS.ServiceName     -- ^Service port to bind.
  -> () -> P.Producer (P.ExceptionP p) B.ByteString P.SafeIO ()
serveReadS mwait ss hp port = \() -> do
   listen id hp port $ \(lsock,_) -> do
     accept id ss lsock $ \(csock,_) -> do
       contextReadS mwait csock ()

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
-- >>> let dst = serveWriteD Nothing settings "example.org" "4433"
-- >>> runSafeIO . runProxy . runEitherK $ fromListS ["He","llo\r\n"] >-> dst
serveWriteD
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> S.ServerSettings   -- ^TLS settings.
  -> S.HostPreference   -- ^Preferred host to bind.
  -> NS.ServiceName     -- ^Service port to bind.
  -> x -> (P.ExceptionP p) x B.ByteString x B.ByteString P.SafeIO r
serveWriteD mwait ss hp port = \x -> do
   listen id hp port $ \(lsock,_) -> do
     accept id ss lsock $ \(csock,_) -> do
       contextWriteD mwait csock x

--------------------------------------------------------------------------------

-- $socket-streaming
--
-- Once you have a an established TLS 'T.Context', you can use the following
-- 'P.Proxy's to interact with the other connection end using pipes streams.

--------------------------------------------------------------------------------

-- | Receives decrypted bytes from the remote end, sending them downstream.
--
-- Up to @16384@ decrypted bytes will be received at once. The TLS connection is
-- automatically renegotiated if a /ClientHello/ message is received.
--
-- If an optional timeout is given and receiveing data from the remote end takes
-- more time that such timeout, then throw a 'Timeout' exception in the
-- 'P.ExceptionP' proxy transformer.
--
-- If the remote peer closes its side of the connection or EOF is reached, this
-- proxy returns.
contextReadS
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> T.Context          -- ^Established TLS connection context.
  -> () -> P.Producer (P.ExceptionP p) B.ByteString P.SafeIO ()
contextReadS Nothing ctx = loop where
    loop () = do
      mbs <- P.tryIO (S.recv ctx)
      case mbs of
        Nothing -> return ()
        Just bs -> P.respond bs >>= loop
contextReadS (Just wait) ctx = loop where
    loop () = do
      mmbs <- P.tryIO (timeout wait (S.recv ctx))
      case mmbs of
        Nothing        -> P.throw ex
        Just Nothing   -> return ()
        Just (Just bs) -> P.respond bs >>= loop
    ex = Timeout $ "contextReadS: " <> show wait <> " microseconds."
{-# INLINABLE contextReadS #-}

-- | Encrypts and sends to the remote end the bytes received from upstream,
-- then forwards such same bytes downstream.
--
-- If an optional timeout is given and sending data to the remote end takes
-- more time that such timeout, then throw a 'Timeout' exception in the
-- 'P.ExceptionP' proxy transformer.
--
-- If the remote peer closes its side of the connection, this proxy returns.
--
-- Requests from downstream are forwarded upstream.
contextWriteD
  :: P.Proxy p
  => Maybe Int          -- ^Optional timeout in microseconds (1/10^6 seconds).
  -> T.Context          -- ^Established TLS connection context.
  -> x -> (P.ExceptionP p) x B.ByteString x B.ByteString P.SafeIO r
contextWriteD Nothing ctx = loop where
    loop x = do
      a <- P.request x
      P.tryIO (S.send ctx a)
      P.respond a >>= loop
contextWriteD (Just wait) ctx = loop where
    loop x = do
      a <- P.request x
      m <- P.tryIO (timeout wait (S.send ctx a))
      case m of
        Just () -> P.respond a >>= loop
        Nothing -> P.throw ex
    ex = Timeout $ "contextWriteD: " <> show wait <> " microseconds."
{-# INLINABLE contextWriteD #-}



--------------------------------------------------------------------------------
-- Internal stuff


-- | Perform a TLS 'T.handshake' on the given 'T.Context', then perform the
-- given action, and at last say 'T.bye' and close the TLS connection, even in
-- case of exceptions. Like 'S.useTls', except it runs within 'P.ExceptionP'.
--
-- This function discards 'Eg.ResourceVanished' exceptions that will happen when
-- trying to say 'T.bye' if the remote end has done it before.
useTls
  :: (Monad m, P.Proxy p)
  => (forall x. P.SafeIO x -> m x) -- ^Monad morphism.
  -> ((T.Context, NS.SockAddr) -> P.ExceptionP p a' a b' b m r)
  -> (T.Context, NS.SockAddr) -> P.ExceptionP p a' a b' b m r
useTls morph k = \conn@(ctx,_) -> do
    P.bracket_ morph (T.handshake ctx) (byeNoVanish ctx) (k conn)
{-# INLINABLE useTls #-}


-- | Like `T.bye`, except it ignores `ResourceVanished` exceptions.
byeNoVanish :: T.Context -> IO ()
byeNoVanish ctx =
    E.handle (\Eg.IOError{Eg.ioe_type=Eg.ResourceVanished} -> return ())
             (T.bye ctx)
{-# INLINABLE byeNoVanish #-}

-- | Like `T.contextClose`, except it ignores `ResourceVanished` exceptions.
contextCloseNoVanish :: T.Context -> IO ()
contextCloseNoVanish = \ctx ->
    E.handle (\Eg.IOError{Eg.ioe_type=Eg.ResourceVanished} -> return ())
             (T.contextClose ctx)
{-# INLINABLE contextCloseNoVanish #-}



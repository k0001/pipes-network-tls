{-# LANGUAGE RankNTypes #-}

-- | This module exports functions that allow you to use TLS-secured
-- TCP connections in a streaming fashion.
--
-- You are encouraged to use this module together with "Network.Simple.TCP.TLS"
-- as follows:
--
-- @
-- import qualified "Network.Simple.TCP.TLS" as TLS
-- import qualified "Pipes.Network.TCP.TLS"  as TLS
-- @
--
-- This module /does not/ export facilities that would allow you to establish
-- new connections within a pipeline. If you need to do so, then you should use
-- "Pipes.Network.TCP.TLS.Safe" instead, which exports a similar API to the one
-- exported by this module. Don't be confused by the word “safe” in that module;
-- this module is equally safe to use as long as you don't try to acquire new
-- resources within the pipeline.

module Pipes.Network.TCP.TLS (
  -- * Receiving
  -- $receiving
    fromContext
  , fromContextTimeout
  -- * Sending
  -- $sending
  , toContext
  , toContextTimeout
  ) where

import           Pipes
import qualified Data.ByteString                as B
import           Foreign.C.Error                (errnoToIOError, eTIMEDOUT)
import           Network.Simple.TCP.TLS
import           System.Timeout                 (timeout)

--------------------------------------------------------------------------------

-- $client-side
--
-- Here's how you could run a simple TLS-secured TCP client:
--
-- @
-- import qualified "Pipes.Network.TCP.TLS"  as TLS
--
-- \ settings <- 'getDefaultClientSettings'
-- 'connect' settings \"www.example.org\" \"443\" $ \(tlsCtx, remoteAddr) -> do
--   putStrLn $ \"Secure connection established to \" ++ show remoteAddr
--   -- now you may use tlsCtx as you please within this scope, possibly with
--   -- the 'fromContext' or 'toContext' proxies explained below.
-- @

--------------------------------------------------------------------------------

-- $server-side
--
-- Here's how you could run a simple TLS-secured TCP server that handles in
-- different threads each incoming connection to port @4433@ at hostname
-- @example.org@. You will need a X509 certificate and a private key appropiate
-- to be used at that hostname.
--
-- @
-- import qualified "Pipes.Network.TCP.TLS"  as TLS
-- import "Network.TLS.Extra" (fileReadCertificate, fileReadPrivateKey)
--
-- \ cert <- 'Network.TLS.Extra.fileReadCertificate' \"~/example.org.crt\"
-- pkey <- 'Network.TLS.Extra.fileReadPrivateKey'  \"~/example.org.key\"
-- let cred = 'Credential' cert pkey []
--     settings = 'makeServerSettings' cred Nothing
--
-- \ 'serve' settings ('Host' \"example.org\") \"4433\" $ \(tlsCtx, remoteAddr) -> do
--   putStrLn $ \"Secure connection established from \" ++ show remoteAddr
--   -- now you may use tlsCtx as you please within this scope, possibly with
--   -- the 'fromContext' or 'toContext' proxies explained below.
-- @
--
-- If you need more control on the way your server runs, then you can use more
-- advanced functions such as 'listen', 'accept' or 'acceptFork'.

--------------------------------------------------------------------------------

-- $sending
--
-- The following pipes allow you to send bytes to the remote end over a
-- TLS-secured TCP connection.
--
-- Besides the pipes below, you might want to use "Network.Simple.TCP.TLS"'s
-- 'Network.Simple.TCP.TLS.send', which happens to be an 'Effect'':
--
-- @
-- 'TLS.send' :: 'MonadIO' m => 'TLS.Context' -> 'B.ByteString' -> 'Effect'' m ()
-- @


-- | Encrypts and sends to the remote end each 'B.ByteString' received from
-- upstream.
toContext
  :: MonadIO m
  => Context          -- ^Established TLS connection context.
  -> Consumer' B.ByteString m r
toContext ctx = for cat (\a -> send ctx a)
{-# INLINABLE toContext #-}

-- | Like 'toContext', except with the first 'Int' argument you can specify
-- the maximum time that each interaction with the remote end can take. If such
-- time elapses before the interaction finishes, then an 'IOError' exception is
-- thrown. The time is specified in microseconds (10e6).
toContextTimeout
  :: MonadIO m
  => Int              -- ^Timeout in microseconds (1/10^6 seconds).
  -> Context          -- ^Established TLS connection context.
  -> Consumer' B.ByteString m r
toContextTimeout wait ctx = for cat $ \a -> do
    mu <- liftIO $ timeout wait (send ctx a)
    case mu of
       Just () -> return ()
       Nothing -> liftIO $ ioError $ errnoToIOError
          "Pipes.Network.TCP.TLS.toContextTimeout" eTIMEDOUT Nothing Nothing
{-# INLINABLE toContextTimeout #-}

--------------------------------------------------------------------------------

-- $receiving
--
-- The following pipes allow you to receive bytes from the remote end over a
-- TLS-secured TCP connection.
--
-- Besides the pipes below, you might want to use "Network.Simple.TCP.TLS"'s
-- 'TLS.recv', which happens to be an 'Effect'':
--
-- @
-- 'TLS.recv' :: 'MonadIO' m => 'TLS.Context' -> 'Effect'' m ('Maybe' 'B.ByteString')
-- @


-- | Receives decrypted bytes from the remote end and sends them downstream.
--
-- The number of bytes received at once is always in the interval
-- /[1 .. 16384]/.
--
-- The TLS connection is automatically renegotiated if a /ClientHello/ message
-- is received.
--
-- This 'Producer'' returns if the remote peer closes its side of the connection
-- or EOF is received.
fromContext
  :: MonadIO m
  => Context          -- ^Established TLS connection context.
  -> Producer' B.ByteString m ()
fromContext ctx = loop where
    loop = do
      mbs <- recv ctx
      case mbs of
        Nothing -> return ()
        Just bs -> yield bs >> loop
{-# INLINABLE fromContext #-}

-- | Like 'fromContext', except with the first 'Int' argument you can specify
-- the maximum time that each interaction with the remote end can take. If such
-- time elapses before the interaction finishes, then an 'IOError' exception is
-- thrown. The time is specified in microseconds (10e6).
fromContextTimeout
  :: MonadIO m
  => Int              -- ^Timeout in microseconds (1/10^6 seconds).
  -> Context          -- ^Established TLS connection context.
  -> Producer' B.ByteString m ()
fromContextTimeout wait ctx = loop where
    loop = do
      mmbs <- liftIO $ timeout wait (recv ctx)
      case mmbs of
         Just (Just bs) -> yield bs >> loop
         Just Nothing   -> return ()
         Nothing        -> liftIO $ ioError $ errnoToIOError
            "Pipes.Network.TCP.TLS.fromContextTimeout" eTIMEDOUT Nothing Nothing
{-# INLINABLE fromContextTimeout #-}

--------------------------------------------------------------------------------

-- $exports

-- The entire "Network.Simple.TCP.TLS" module is exported.

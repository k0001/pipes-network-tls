-- | This module exports functions that allow you to use TLS-secured
-- TCP connections as streams, as well as utilities to connect to a
-- TLS-enabled TCP server or running your own.
--
-- If you need to safely connect to a TLS-enabled TCP server or run your own
-- /within/ a pipes pipeline, then you /must/ use the functions exported from
-- the module "Control.Proxy.TCP.TLS.Safe" instead.
--
-- This module re-exports many functions and types from "Network.Simple.TCP.TLS"
-- module in the @network-simple@ package. You might refer to that module for
-- more documentation.

module Control.Proxy.TCP.TLS (
  -- * Client side
  -- $client-side
    S.connect
  , S.ClientSettings
  , S.getDefaultClientSettings
  , S.makeClientSettings

  -- * Server side
  -- $server-side
  , S.serve
  , S.ServerSettings
  , S.makeServerSettings
  -- ** Listening
  , S.listen
  -- ** Accepting
  , S.accept
  , S.acceptFork

  -- * TLS context streams
  -- $socket-streaming
  , contextReadS
  , contextWriteD
  -- ** Timeouts
  -- $socket-streaming-timeout
  , contextReadTimeoutS
  , contextWriteTimeoutD

  -- * Note to Windows users
  -- $windows-users
  , S.withSocketsDo

  -- * Exports
  , S.HostPreference(..)
  , S.Credential(..)
  , Timeout(..)
  ) where

import           Control.Monad.Trans.Class
import qualified Control.Proxy                  as P
import           Control.Proxy.TCP              (Timeout(..))
import qualified Control.Proxy.Trans.Either     as PE
import qualified Data.ByteString                as B
import           Data.Monoid
import qualified Network.Simple.TCP.TLS         as S
import qualified Network.TLS                    as T
import           System.Timeout                 (timeout)

--------------------------------------------------------------------------------

-- $windows-users
--
-- If you are running Windows, then you /must/ call 'S.withSocketsDo', just
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
-- main = 'S.withSocketsDo' $ do
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
-- @
-- import "Control.Proxy.TCP.TLS"
--
-- \ settings <- 'S.getDefaultClientSettings'
-- 'S.connect' settings \"www.example.org\" \"443\" $ \(tlsCtx, remoteAddr) -> do
--   putStrLn $ \"Secure connection established to \" ++ show remoteAddr
--   -- now you may use tlsCtx as you please within this scope, possibly with
--   -- the 'contextReadS' or 'contextWriteD' proxies explained below.
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
-- import "Control.Proxy.TCP.TLS"
-- import "Network.TLS.Extra" (fileReadCertificate, fileReadPrivateKey)
--
-- \ cert <- 'Network.TLS.Extra.fileReadCertificate' \"~/example.org.crt\"
-- pkey <- 'Network.TLS.Extra.fileReadPrivateKey'  \"~/example.org.key\"
-- let cred = 'S.Credential' cert pkey []
--     settings = 'S.makeServerSettings' cred Nothing
--
-- \ 'S.serve' settings ('S.Host' \"example.org\") \"4433\" $ \(tlsCtx, remoteAddr) -> do
--   putStrLn $ \"Secure connection established from \" ++ show remoteAddr
--   -- now you may use tlsCtx as you please within this scope, possibly with
--   -- the 'contextReadS' or 'contextWriteD' proxies explained below.
-- @
--
-- If you need more control on the way your server runs, then you can use more
-- advanced functions such as 'S.listen', 'S.accept' and 'S.acceptFork'.

--------------------------------------------------------------------------------

-- $socket-streaming
--
-- Once you have an established TLS connection 'T.Context', then you can use the
-- following 'P.Proxy's to interact with the other connection end using streams.

-- | Receives decrypted bytes from the remote end, sending them downstream.
--
-- Up to @16384@ decrypted bytes will be received at once. The TLS connection is
-- automatically renegotiated if a /ClientHello/ message is received.
--
-- If the remote peer closes its side of the connection or EOF is reached,
-- this proxy returns.
contextReadS
  :: P.Proxy p
  => T.Context          -- ^Established TLS connection context.
  -> () -> P.Producer p B.ByteString IO ()
contextReadS ctx = P.runIdentityK loop where
    loop () = do
      mbs <- lift (S.recv ctx)
      case mbs of
        Just bs -> P.respond bs >>= loop
        Nothing -> return ()
{-# INLINABLE contextReadS #-}

-- | Encrypts and sends to the remote end the bytes received from upstream,
-- then forwards such same bytes downstream.
--
-- If the remote peer closes its side of the connection, this proxy returns.
--
-- Requests from downstream are forwarded upstream.
contextWriteD
  :: P.Proxy p
  => T.Context          -- ^Established TLS connection context.
  -> x -> p x B.ByteString x B.ByteString IO r
contextWriteD ctx = P.runIdentityK loop where
    loop x = do
      a <- P.request x
      lift (S.send ctx a)
      P.respond a >>= loop
{-# INLINABLE contextWriteD #-}

--------------------------------------------------------------------------------

-- $socket-streaming-timeout
--
-- These proxies behave like the similarly named ones above, except they support
-- timing out the interaction with the remote end.

-- | Like 'contextReadS', except it throws a 'Timeout' exception in the
-- 'PE.EitherP' proxy transformer if receiving data from the remote end takes
-- more time than specified.
contextReadTimeoutS
  :: P.Proxy p
  => Int                -- ^Timeout in microseconds (1/10^6 seconds).
  -> T.Context          -- ^Established TLS connection context.
  -> () -> P.Producer (PE.EitherP Timeout p) B.ByteString IO ()
contextReadTimeoutS wait ctx = loop where
    loop () = do
      mmbs <- lift (timeout wait (S.recv ctx))
      case mmbs of
        Just (Just bs) -> P.respond bs >>= loop
        Just Nothing   -> return ()
        Nothing        -> PE.throw ex
    ex = Timeout $ "contextReadTimeoutS: " <> show wait <> " microseconds."
{-# INLINABLE contextReadTimeoutS #-}

-- | Like 'contextWriteD', except it throws a 'Timeout' exception in the
-- 'PE.EitherP' proxy transformer if sending data to the remote end takes
-- more time than specified.
contextWriteTimeoutD
  :: P.Proxy p
  => Int                -- ^Timeout in microseconds (1/10^6 seconds).
  -> T.Context          -- ^Established TLS connection context.
  -> x -> (PE.EitherP Timeout p) x B.ByteString x B.ByteString IO r
contextWriteTimeoutD wait ctx = loop where
    loop x = do
      a <- P.request x
      m <- lift (timeout wait (S.send ctx a))
      case m of
        Just () -> P.respond a >>= loop
        Nothing -> PE.throw ex
    ex = Timeout $ "contextWriteTimeoutD: " <> show wait <> " microseconds."
{-# INLINABLE contextWriteTimeoutD #-}


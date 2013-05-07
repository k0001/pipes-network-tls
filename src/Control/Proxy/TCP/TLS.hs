-- | This module exports functions that allow you to use TLS-secured
-- TCP connections as streams, as well as utilities to connect to a
-- TLS-enabled TCP server or running your own.
--
-- If you need to safely connect to a TLS-enabled TCP server or run your own
-- /within/ a pipes pipeline, then you /must/ use the functions exported from
-- the module "Control.Proxy.TCP.TLS.Safe" instead.
--
-- This module re-exports many functions from "Network.Simple.TCP.TLS"
-- module in the @network-simple@ package. You might refer to that
-- module for more documentation.

module Control.Proxy.TCP.TLS (
  -- * Server side
  -- $server-side
    S.serve
  -- ** Listening
  , S.listen
  -- ** Accepting
  , S.accept
  , S.acceptFork

  -- * Client side
  -- $client-side
  , S.connect

  -- * TLS context streams
  -- $socket-streaming
  , tlsReadS
  , ntlsReadS
  , tlsWriteD
  -- ** Timeouts
  -- $socket-streaming-timeout
  , tlsReadTimeoutS
  , ntlsReadTimeoutS
  , tlsWriteTimeoutD

  -- * Exports
  , S.HostPreference(..)
  , Timeout(..)
  ) where

import           Control.Monad.Trans.Class
import qualified Control.Proxy                  as P
import           Control.Proxy.TCP              (Timeout(..))
import           Control.Proxy.TCP.TLS.Internal (recvN)
import qualified Control.Proxy.Trans.Either     as PE
import qualified Data.ByteString                as B
import qualified Data.ByteString.Lazy           as BL
import           Data.Monoid
import qualified Network.Simple.TCP.TLS         as S
import qualified Network.TLS                    as T
import           System.Timeout                 (timeout)

--------------------------------------------------------------------------------

-- $client-side
--
-- The following functions allow you to obtain and use TLS 'T.Context's useful
-- to the client side of a TLS-secured TCP connection.
--
-- Here's how you could run a simple TLS-secured TCP client:
--
-- > settings <- getDefaultClientSettings
-- >
-- > connect settings "www.example.org" "443" $ \(tlsCtx, remoteAddr) -> do
-- >   putStrLn $ "Secure connection established to " ++ show remoteAddr
-- >   -- now you may use tlsCtx as you please within this scope, possibly with
-- >   -- the socketReadS, nsocketReadS or socketWriteD proxies explained below.

--------------------------------------------------------------------------------

-- $server-side
--
-- The following functions allow you to obtain and use TLS 'T.Context's useful
-- to the server side of a TLS-secured TCP connection.
--
-- Here's how you could run a simple TLS-secured TCP server that handles in ]
-- different threads each incoming connection to port @4433@ at hostname
-- @example.org@. You will need a X509 certificate and a private key appropiate
-- to be used at that hostname.
--
-- > import Network.TLS.Extra (fileReadCertificate, fileReadPrivateKey)
-- >
-- > cert <- fileReadCertificate "~/example.org.crt"
-- > pkey <- fileReadPrivateKey  "~/example.org.key"
-- > let settings = serverSettings cert pkey Nothing
-- >
-- > serve settings (Host "example.org") "4433" $ \(tlsCtx, remoteAddr) -> do
-- >   putStrLn $ "Secure connection established from " ++ show remoteAddr
-- >   -- now you may use tlsCtx as you please within this scope, possibly with
-- >   -- the socketReadS, nsocketReadS or socketWriteD proxies explained below.
--
-- If you need to control the way your server runs, then you can use more
-- advanced functions such as 'listen', 'accept' and 'acceptFork'.

--------------------------------------------------------------------------------

-- $socket-streaming
--
-- Once you have an established TLS connection 'T.Context', then you can use the
-- following 'P.Proxy's to interact with the other connection end using streams.

-- | Receives bytes from the remote end sends them downstream.
--
-- Less than the specified maximum number of bytes might be received at once.
--
-- If the remote peer closes its side of the connection, this proxy returns.
tlsReadS
  :: P.Proxy p
  => Int                -- ^Maximum number of bytes to receive at once.
  -> T.Context          -- ^Established TLS connection context.
  -> () -> P.Producer p B.ByteString IO ()
tlsReadS nbytes ctx () = P.runIdentityP loop where
    loop = do
      mbs <- lift $ recvN ctx nbytes
      case mbs of
        Just bs -> P.respond bs >> loop
        Nothing -> return ()
{-# INLINABLE tlsReadS #-}

-- | Just like 'socketReadS', except each request from downstream specifies the
-- maximum number of bytes to receive.
ntlsReadS
  :: P.Proxy p
  => T.Context          -- ^Established TLS connection context.
  -> Int -> P.Server p Int B.ByteString IO ()
ntlsReadS ctx = P.runIdentityK loop where
    loop nbytes = do
      mbs <- lift $ recvN ctx nbytes
      case mbs of
        Just bs -> P.respond bs >>= loop
        Nothing -> return ()
{-# INLINABLE ntlsReadS #-}

-- | Sends to the remote end the bytes received from upstream, then forwards
-- such same bytes downstream.
--
-- Requests from downstream are forwarded upstream.
tlsWriteD
  :: P.Proxy p
  => T.Context          -- ^Established TLS connection context.
  -> x -> p x B.ByteString x B.ByteString IO r
tlsWriteD ctx = P.runIdentityK loop where
    loop x = do
      a <- P.request x
      lift $ T.sendData ctx (BL.fromChunks [a])
      P.respond a >>= loop
{-# INLINABLE tlsWriteD #-}

--------------------------------------------------------------------------------

-- $socket-streaming-timeout
--
-- These proxies behave like the similarly named ones above, except support for
-- timing out the interaction with the remote end is added.

-- | Like 'socketReadS', except it throws a 'Timeout' exception in the
-- 'PE.EitherP' proxy transformer if receiving data from the remote end takes
-- more time than specified.
tlsReadTimeoutS
  :: P.Proxy p
  => Int                -- ^Timeout in microseconds (1/10^6 seconds).
  -> Int                -- ^Maximum number of bytes to receive at once.
  -> T.Context          -- ^Established TLS connection context.
  -> () -> P.Producer (PE.EitherP Timeout p) B.ByteString IO ()
tlsReadTimeoutS wait nbytes ctx () = loop where
    loop = do
      mmbs <- lift . timeout wait $ recvN ctx nbytes
      case mmbs of
        Just (Just bs) -> P.respond bs >> loop
        Just Nothing   -> return ()
        Nothing        -> PE.throw ex
    ex = Timeout $ "tlsReadTimeoutS: " <> show wait <> " microseconds."
{-# INLINABLE tlsReadTimeoutS #-}

-- | Like 'nsocketReadS', except it throws a 'Timeout' exception in the
-- 'PE.EitherP' proxy transformer if receiving data from the remote end takes
-- more time than specified.
ntlsReadTimeoutS
  :: P.Proxy p
  => Int                -- ^Timeout in microseconds (1/10^6 seconds).
  -> T.Context          -- ^Established TLS connection context.
  -> Int -> P.Server (PE.EitherP Timeout p) Int B.ByteString IO ()
ntlsReadTimeoutS wait ctx = loop where
    loop nbytes = do
      mmbs <- lift . timeout wait $ recvN ctx nbytes
      case mmbs of
        Just (Just bs) -> P.respond bs >>= loop
        Just Nothing   -> return ()
        Nothing        -> PE.throw ex
    ex = Timeout $ "ntlsReadTimeoutS: " <> show wait <> " microseconds."
{-# INLINABLE ntlsReadTimeoutS #-}

-- | Like 'socketWriteD', except it throws a 'Timeout' exception in the
-- 'PE.EitherP' proxy transformer if sending data to the remote end takes
-- more time than specified.
tlsWriteTimeoutD
  :: P.Proxy p
  => Int                -- ^Timeout in microseconds (1/10^6 seconds).
  -> T.Context          -- ^Established TLS connection context.
  -> x -> (PE.EitherP Timeout p) x B.ByteString x B.ByteString IO r
tlsWriteTimeoutD wait ctx = loop where
    loop x = do
      a <- P.request x
      m <- lift . timeout wait $ T.sendData ctx (BL.fromChunks [a])
      case m of
        Just () -> P.respond a >>= loop
        Nothing -> PE.throw ex
    ex = Timeout $ "tlsWriteTimeoutD: " <> show wait <> " microseconds."
{-# INLINABLE tlsWriteTimeoutD #-}


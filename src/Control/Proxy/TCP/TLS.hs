-- | This module exports functions that allow you to safely use TLS-secured
-- TCP connections established outside a 'P.Proxy' pipeline within pipes
-- streams.
--
-- Instead, if want to safely acquire and release resources within the
-- pipeline itself, then you should use the functions exported by
-- "Control.Proxy.TCP.Safe".
--
-- This module re-exports many functions from "Network.Simple.TCP"
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

  -- * Socket streams
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

import qualified Control.Exception              as E
import           Control.Monad.Trans.Class
import qualified Control.Proxy                  as P
import qualified Control.Proxy.Trans.Either     as PE
import           Control.Proxy.TCP              (Timeout(..))
import qualified Data.ByteString                as B
import qualified Data.ByteString.Lazy           as BL
import           Data.Monoid
import qualified Network.Simple.TCP.TLS         as S
import qualified Network.TLS                    as T
import           System.Timeout                 (timeout)

--------------------------------------------------------------------------------

-- $client-side
--
-- The following functions allow you to obtain and use 'NS.Socket's useful to
-- the client side of a TCP connection.
--
-- Here's how you could run a TCP client:
--
-- > connect "www.example.org" "80" $ \(connectionSocket, remoteAddr) -> do
-- >   putStrLn $ "Connection established to " ++ show remoteAddr
-- >   -- now you may use connectionSocket as you please within this scope,
-- >   -- possibly with any of the socketReadS, nsocketReadS or socketWriteD
-- >   -- proxies explained below.

--------------------------------------------------------------------------------

-- $server-side
--
-- The following functions allow you to obtain and use 'NS.Socket's useful to
-- the server side of a TCP connection.
--
-- Here's how you could run a TCP server that handles in different threads each
-- incoming connection to port @8000@ at address @127.0.0.1@:
--
-- > listen (Host "127.0.0.1") "8000" $ \(listeningSocket, listeningAddr) -> do
-- >   putStrLn $ "Listening for incoming connections at " ++ show listeningAddr
-- >   forever . acceptFork listeningSocket $ \(connectionSocket, remoteAddr) -> do
-- >     putStrLn $ "Connection established from " ++ show remoteAddr
-- >     -- now you may use connectionSocket as you please within this scope,
-- >     -- possibly with any of the socketReadS, nsocketReadS or socketWriteD
-- >     -- proxies explained below.
--
-- If you keep reading you'll discover there are different ways to achieve
-- the same, some ways more general than others. The above one was just an
-- example using a pretty general approach, you are encouraged to use simpler
-- approaches such as 'serve' if those suit your needs.

--------------------------------------------------------------------------------

-- $socket-streaming
--
-- Once you have a connected 'NS.Socket', you can use the following 'P.Proxy's
-- to interact with the other connection end using streams.

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

--------------------------------------------------------------------------------

recvN :: T.Context -> Int -> IO (Maybe B.ByteString)
recvN ctx nbytes = do
    ebs <- E.try (T.backendRecv (T.ctxConnection ctx) nbytes)
    case ebs of
      Right bs | B.null bs -> return Nothing
               | otherwise -> return (Just bs)
      Left T.Error_EOF     -> return Nothing
      Left e               -> E.throwIO e
{-# INLINE recvN #-}

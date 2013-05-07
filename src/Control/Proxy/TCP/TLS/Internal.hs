{-# LANGUAGE Rank2Types #-}

-- | This module exports functions not intended for public use and subject to
-- change in the future without notice.

module Control.Proxy.TCP.TLS.Internal (
    useTlsThenClose
  ) where

import qualified Control.Exception               as E
import qualified Control.Proxy                   as P
import qualified Control.Proxy.Safe              as P
import qualified GHC.IO.Exception                as Eg
import qualified Network.Socket                  as NS
import qualified Network.TLS                     as T
-- Imported for Haddock
import qualified Network.Simple.TCP.TLS.Internal as Si

--------------------------------------------------------------------------------

-- | Perform a TLS 'T.handshake' on the given 'T.Context', then perform the
-- given action, and at last close the TLS connection, even in case of
-- exceptions. Like 'Si.useTlsThenClose', except it runs within
-- 'P.ExceptionP'.
useTlsThenClose
  :: (Monad m, P.Proxy p)
  => (forall x. P.SafeIO x -> m x) -- ^Monad morphism.
  -> ((T.Context, NS.SockAddr) -> P.ExceptionP p a' a b' b m r)
  -> (T.Context, NS.SockAddr) -> P.ExceptionP p a' a b' b m r
useTlsThenClose morph k conn@(ctx,_) =
    P.finally morph (contextClose' ctx)
                    (do P.hoist morph (P.tryIO (T.handshake ctx))
                        P.finally morph (bye' ctx) (k conn))
  where
    -- If the remote end closes the connection first we might get some
    -- exceptions. These wrappers work around those exceptions.
    contextClose' = ignoreResourceVanishedErrors . T.contextClose
    bye'          = ignoreResourceVanishedErrors . T.bye
{-# INLINE useTlsThenClose #-}

-- | Perform the given action, swallowing any 'E.IOException' of type
-- 'Eg.ResourceVanished' if it happens.
ignoreResourceVanishedErrors :: IO () -> IO ()
ignoreResourceVanishedErrors = E.handle (\e -> case e of
    Eg.IOError{} | Eg.ioe_type e == Eg.ResourceVanished -> return ()
    _ -> E.throwIO e)
{-# INLINE ignoreResourceVanishedErrors #-}

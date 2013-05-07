-- | This module exports functions not intended for public use and subject to
-- change in the future without notice.

module Control.Proxy.TCP.TLS.Internal (
    recvN
  ) where

import qualified Control.Exception              as E
import qualified Data.ByteString                as B
import qualified Network.TLS                    as T

--------------------------------------------------------------------------------

-- | Receives up to a limited number of bytes from the given 'T.Context'.
-- Returns 'Nothing' on EOF.
recvN :: T.Context -> Int -> IO (Maybe B.ByteString)
recvN ctx nbytes = do
    ebs <- E.try (T.backendRecv (T.ctxConnection ctx) nbytes)
    case ebs of
      Right bs | B.null bs -> return Nothing
               | otherwise -> return (Just bs)
      Left T.Error_EOF     -> return Nothing
      Left e               -> E.throwIO e
{-# INLINE recvN #-}

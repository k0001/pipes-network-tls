module Control.Proxy.TCP.TLS.Internal (
    contextCloseNoVanish
  , byeNoVanish
  , Timeout(..)
  ) where

import qualified Control.Exception              as E
import           Control.Proxy.TCP              (Timeout(..))
import qualified GHC.IO.Exception               as Eg
import qualified Network.TLS                    as T


--------------------------------------------------------------------------------
-- These two are defined internally in @network-simple-tls@ but they are not
-- exported, so we redefine them here.

-- | Like `T.contextClose`, except it ignores `ResourceVanished` exceptions.
contextCloseNoVanish :: T.Context -> IO ()
contextCloseNoVanish ctx =
    E.handle (\Eg.IOError{Eg.ioe_type=Eg.ResourceVanished} -> return ())
             (T.contextClose ctx)
{-# INLINE contextCloseNoVanish #-}

-- | Like `T.bye`, except it ignores `ResourceVanished` exceptions.
byeNoVanish :: T.Context -> IO ()
byeNoVanish ctx =
    E.handle (\Eg.IOError{Eg.ioe_type=Eg.ResourceVanished} -> return ())
             (T.bye ctx)
{-# INLINE byeNoVanish #-}

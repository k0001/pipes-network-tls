module Control.Proxy.TCP.TLS.Internal (
    recv
  , send
  , contextCloseNoVanish
  , byeNoVanish
  , Timeout(..)
  ) where

import qualified Control.Exception              as E
import           Control.Proxy.TCP              (Timeout(..))
import qualified Data.ByteString                as B
import qualified GHC.IO.Exception               as Eg
import qualified Network.Simple.TCP.TLS         as S
import qualified Network.TLS                    as T

--------------------------------------------------------------------------------

-- | Like `S.recv`, except it also returns `Nothing` if the remote end closed
-- the connection (“Broken Pipe”).
recv :: T.Context -> IO (Maybe B.ByteString)
recv ctx =
    E.handle (\Eg.IOError{Eg.ioe_type=Eg.ResourceVanished} -> return Nothing)
             (S.recv ctx)
{-# INLINE recv #-}

-- | Like `S.send`, except it also returns `True` on success and `False` if
-- the remote end closed the connection (“Broken Pipe”).
send :: T.Context -> B.ByteString -> IO Bool
send ctx bs =
    E.handle (\Eg.IOError{Eg.ioe_type=Eg.ResourceVanished} -> return False)
             (S.send ctx bs >> return True)
{-# INLINE send #-}

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

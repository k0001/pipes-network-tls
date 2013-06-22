{-# LANGUAGE BangPatterns #-}

-- Yeah, yeah... I know. This code could be a bit more organized.

module Main (main) where

import           Control.Concurrent.Async   as A
import           Control.Applicative
import           Control.Proxy              ((>->))
import qualified Control.Proxy              as P
import qualified Control.Proxy.TCP.TLS      as Pt
import           Data.Certificate.X509      (X509)
import           Data.Maybe                 (maybeToList)
import           Data.Monoid                ((<>))
import qualified Network.Socket             as NS
import qualified Network.TLS                as T
import           Network.TLS.Extra          as TE
import           System.Certificate.X509    (getSystemCertificateStore)
import           System.Console.GetOpt
import           System.Environment         (getProgName, getArgs)
import qualified Data.CertificateStore      as C

runTlsTunnel
  :: Pt.ServerSettings       -- ^Local server settings
  -> Pt.HostPreference       -- ^Local host to bind
  -> NS.ServiceName          -- ^Local port to bind
  -> Pt.ClientSettings       -- ^Client to remote server settings.
  -> NS.HostName             -- ^Remote host name to connect to
  -> NS.ServiceName          -- ^Remote tcp port to connect to
  -> IO ()
runTlsTunnel sS sHp sPort cS cHost cPort = do
    Pt.serve sS sHp sPort $ \(sCtx, sAddr) -> do
        let sMsg = show sAddr
        putStrLn $ sMsg <> " joined."
        putStrLn $ sMsg <> " is being tunneled to " <> show (cHost, cPort)
        Pt.connect cS cHost cPort $ \(cCtx, cAddr) -> do
            let cMsg = "Secure connection to " <> show cAddr
            putStrLn $ cMsg <> " established."
            a1 <- A.async . P.runProxy $ Pt.contextReadS sCtx >-> Pt.contextWriteD cCtx
            P.runProxy $ Pt.contextReadS cCtx >-> Pt.contextWriteD sCtx
            A.wait a1
            putStrLn $ cMsg <> " closed."
        putStrLn $ sMsg <> " quit."


main :: IO ()
main = Pt.withSocketsDo $ do
    args <- getArgs
    case getOpt RequireOrder options args of
      (actions, [locHost,locPort,remHost,remPort], _) -> do
        opts <- foldl (>>=) (return defaultOptions) actions
        let !sCred = Pt.Credential (optLocalCert opts) (optLocalKey opts) []
            smcStore = C.makeCertificateStore . pure <$> optLocalCACert opts
            sS = Pt.makeServerSettings sCred smcStore
        ccStore <- case optRemoteCACert opts of
                     Nothing -> getSystemCertificateStore
                     Just ca -> return $ C.makeCertificateStore [ca]
        let !cCreds = maybeToList $ Pt.Credential <$> optRemoteCert opts
                                                  <*> optRemoteKey opts
                                                  <*> pure []
            cS = Pt.makeClientSettings cCreds (Nothing) ccStore
        runTlsTunnel sS (Pt.Host locHost) locPort cS remHost remPort
      (_,_,msgs) -> do
        pn <- getProgName
        let header = "Usage: " <> pn
              <> " [OPTIONS] LOCAL-HOST LOCAL-PORT REMOTE-HOST REMOTE-PORT"
        error $ concat msgs ++ usageInfo header options


--------------------------------------------------------------------------------
-- The boring stuff below is related to command line parsing


data Options = Options
  { optLocalCert    :: X509
  , optLocalKey     :: T.PrivateKey
  , optLocalCACert  :: Maybe X509
  , optRemoteCert   :: Maybe X509
  , optRemoteKey    :: Maybe T.PrivateKey
  , optRemoteCACert :: Maybe X509
  } deriving (Show)

defaultOptions :: Options
defaultOptions = Options
  { optLocalCert    = error "Missing optLocalCert"
  , optLocalKey     = error "Missing optLocalKey"
  , optLocalCACert  = Nothing
  , optRemoteCert   = Nothing
  , optRemoteKey    = Nothing
  , optRemoteCACert = Nothing
  }

options :: [OptDescr (Options -> IO Options)]
options =
  [ Option [] ["lcert"]   (ReqArg readLocalCert    "FILE")
    "Local server certificate"
  , Option [] ["lkey"]    (ReqArg readLocalKey     "FILE")
    "Local server private key"
  , Option [] ["lcacert"] (OptArg readLocalCACert  "FILE")
    "If given, request a client certificate for incomming connections\
    \ and verify it against this CA."
  , Option [] ["rcert"]   (OptArg readRemoteCert   "FILE")
    "Certificate to provide to remote server if requested"
  , Option [] ["rkey"]    (OptArg readRemoteKey    "FILE")
    "Key to use together with 'rcert', if requested"
  , Option [] ["rcacert"] (OptArg readRemoteCACert "FILE")
    "If given, verify the remote server certificate using this CA,\
    \ otherwise use the operating system default CAs."
  ]

readLocalCert :: FilePath -> Options -> IO Options
readLocalCert arg opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optLocalCert = cert }

readLocalKey :: FilePath -> Options -> IO Options
readLocalKey arg opt = do
    key <- TE.fileReadPrivateKey arg
    return $ opt { optLocalKey = key }

readLocalCACert :: Maybe FilePath -> Options -> IO Options
readLocalCACert Nothing    opt = return opt
readLocalCACert (Just arg) opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optLocalCACert = Just cert }

readRemoteCert :: Maybe FilePath -> Options -> IO Options
readRemoteCert Nothing    opt = return opt
readRemoteCert (Just arg) opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optRemoteCert = Just cert }

readRemoteKey :: Maybe FilePath -> Options -> IO Options
readRemoteKey Nothing    opt = return opt
readRemoteKey (Just arg) opt = do
    key <- TE.fileReadPrivateKey arg
    return $ opt { optRemoteKey = Just key }

readRemoteCACert :: Maybe FilePath -> Options -> IO Options
readRemoteCACert Nothing    opt = return opt
readRemoteCACert (Just arg) opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optRemoteCACert = Just cert }

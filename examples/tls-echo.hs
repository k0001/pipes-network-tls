{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import           Control.Applicative
import           Pipes
import qualified Pipes.Prelude              as P
import qualified Data.ByteString.Char8      as B
import           Data.Certificate.X509      (X509)
import           Data.Char                  (toUpper)
import           Data.Monoid                ((<>))
import qualified Network.Simple.TCP.TLS     as TLS
import qualified Pipes.Network.TCP.TLS      as TLS
import           Network.TLS.Extra          as TE
import qualified Network.TLS                as T
import           System.Console.GetOpt
import           System.Environment         (getProgName, getArgs)
import qualified Data.CertificateStore      as C

server :: TLS.Credential -> TLS.HostPreference -> TLS.ServiceName
       -> Maybe C.CertificateStore -> IO ()
server cred hp port mcs = do
    let ss = TLS.makeServerSettings cred mcs
    TLS.serve ss hp port $ \(ctx,caddr) -> do
       putStrLn $ show caddr <> " joined."
       runEffect $ TLS.fromContext ctx >-> P.map (B.map toUpper) >-> TLS.toContext ctx
       putStrLn $ show caddr <> " quit."

main :: IO ()
main = TLS.withSocketsDo $ do
    args <- getArgs
    case getOpt RequireOrder options args of
      (actions, [hostname,port], _) -> do
        opts <- foldl (>>=) (return defaultOptions) actions
        let !cred = TLS.Credential (optServerCert opts) (optServerKey opts) []
        server cred (TLS.Host hostname) port
               (C.makeCertificateStore . pure <$> optCACert opts)
      (_,_,msgs) -> do
        pn <- getProgName
        let header = "Usage: " <> pn <> " [OPTIOTLS] HOSTNAME PORT"
        error $ concat msgs ++ usageInfo header options

--------------------------------------------------------------------------------
-- The boring stuff below is related to command line parsing

data Options = Options
  { optServerCert :: X509
  , optServerKey  :: T.PrivateKey
  , optCACert     :: Maybe X509
  } deriving (Show)

defaultOptions :: Options
defaultOptions = Options
  { optServerCert = error "Missing optServerCert"
  , optServerKey  = error "Missing optServerKey"
  , optCACert     = Nothing
  }

options :: [OptDescr (Options -> IO Options)]
options =
  [ Option [] ["cert"]   (ReqArg readServerCert "FILE") "Server certificate"
  , Option [] ["key"]    (ReqArg readServerKey  "FILE") "Server private key"
  , Option [] ["cacert"] (OptArg readCACert     "FILE")
    "CA certificate to verify a client certificate, if given"
  ]

readServerCert :: FilePath -> Options -> IO Options
readServerCert arg opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optServerCert = cert }

readServerKey :: FilePath -> Options -> IO Options
readServerKey arg opt = do
    key <- TE.fileReadPrivateKey arg
    return $ opt { optServerKey = key }

readCACert :: Maybe FilePath -> Options -> IO Options
readCACert Nothing    opt = return opt
readCACert (Just arg) opt = do
    cert <- TE.fileReadCertificate arg
    return $ opt { optCACert = Just cert }


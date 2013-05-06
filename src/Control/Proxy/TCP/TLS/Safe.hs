-- | This module exports functions that allow you to use TLS-secured
-- TCP connections as 'P.Proxy' streams, as well as utilities to connect to a
-- TLS-enabled TCP server or running your own, possibly within the pipeline
-- itself, by relying on the facilities provided by -- 'P.ExceptionP' from the
-- @pipes-safe@ library.
--
-- Instead, if just want to use resources already acquired or released outside
-- the pipeline, then you could use the simpler and similar functions exported
-- by "Control.Proxy.TCP.TLS".


module Control.Proxy.TCP.TLS.Safe where

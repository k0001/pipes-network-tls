{ mkDerivation, base, bytestring, network, network-simple
, network-simple-tls, pipes, pipes-network, pipes-safe, stdenv, tls
, transformers
}:
mkDerivation {
  pname = "pipes-network-tls";
  version = "0.4";
  src = ./.;
  libraryHaskellDepends = [
    base bytestring network network-simple network-simple-tls pipes
    pipes-network pipes-safe tls transformers
  ];
  homepage = "https://github.com/k0001/pipes-network-tls";
  description = "TLS-secured network connections support for pipes";
  license = stdenv.lib.licenses.bsd3;
}

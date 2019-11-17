{ pkgs }:

let
src-pipes-network = builtins.fetchGit {
  url = "https://github.com/k0001/pipes-network";
  rev = "9268b3a42856889fe3c189e271297be9967be9d6";
};
src-network-simple-tls = builtins.fetchGit {
  url = "https://github.com/k0001/network-simple-tls";
  rev = "97a07544c2a504ff9f0d38b4b4ddf26286949b71";
};

in
# This expression can be used as a Haskell package set `packageSetConfig`:
pkgs.lib.composeExtensions
  (pkgs.lib.composeExtensions
    (import "${src-pipes-network}/hs-overlay.nix" { inherit pkgs; })
    (import "${src-network-simple-tls}/hs-overlay.nix" { inherit pkgs; }))
  (self: super: {
     pipes-network-tls = super.callPackage ./pkg.nix {};
  })

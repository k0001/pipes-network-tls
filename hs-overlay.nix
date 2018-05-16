{ pkgs }:

let
src-pipes-network = builtins.fetchGit {
  url = "https://github.com/k0001/pipes-network";
  rev = "9e08bab046a8132f06ebdfefa6b0184a457877c0";
};
src-network-simple-tls = builtins.fetchGit {
  url = "https://github.com/k0001/network-simple-tls";
  rev = "caa207faaa7f48c846780d164fffbafa7b2de612";
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

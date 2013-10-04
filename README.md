# pipes-network-tls

Utilities to deal with TLS-secured network connections using the
**pipes**, **pipes-safe** and **tls** libraries.

Currently, only TCP sockets are supported.

Check the source or rendered Haddocks for extensive documentation.

This code is licensed under the terms of the so called **3-clause BSD
license**. Read the file named ``LICENSE`` found in this same directory
for details.

See the ``PEOPLE`` file to learn about the people involved in this
effort.

## Building the development version

Use [cabal-meta](http://hackage.haskell.org/package/cabal-meta):

    cabal sandbox init
    cabal-meta install -j

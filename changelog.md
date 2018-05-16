# Version 0.3

* BREAKING CHANGE: We now depend on `network-simple-0.3`, which introduced some
  breaking changes. Please refer to its
  [changelog](https://hackage.haskell.org/package/network-simple-0.3/changelog).

* Remove `Pipes.Safe.Base m ~ IO` constraints.

* Remove upper-bound constraints on all dependencies other than `base`.


# Version 0.2.1

* Dependency bumps.


# Version 0.2.0

* Significantly upgraded the API and renamed functions to play well with
  pipes-4.0, pipes-safe-2.0, pipes-network-0.6 and
  network-simple-tls-0.2.

* Throw `IOError` in `IO` in order to report timeout errors. Delete
  the `Timeout` data-type.


# Version 0.1.1.0

* Re-export `Network.Socket.withSocketsDo`


# Version 0.1.0.0

* First release.

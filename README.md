# OpenSC.tokend

### The open source OS X smart card driver

A *tokend* makes the keys and certificates on your smart card appear in *Keychain Access.app* and available to applications like Safari or Chrome. OpenSC.tokend is the **open source** *tokend* implementation from OpenSC, with support for many different real world PKI smart cards found in the wild.

#### History of *tokend* support in OS X

  * In 2005, with OS X version 10.4 "Tiger" Apple introduced the *tokend* middleware to make 3rd party smart cards available to other native OS X applications [[1]](http://manuals.info.apple.com/MANUALS/0/MA336/en_US/Smart_Card_Setup_Guide.pdf). Build instructions for a *tokend* were not publicly available.
  * OS X 10.5 "Leopard" can be considered a stabilization release, where early versions had several bugs that made using smart cards (including a *tokend*) a real pain [[2]](http://web.archive.org/web/20111002054544/http://www.opensc-project.org/sca/wiki/LeopardBugs). With 10.5.6, Apple switched from a homebuilt smart card reader driver to the more feature complete, de facto standard open source CCID driver maintained by Ludovic Rousseau [[3]](http://ludovicrousseau.blogspot.com/2014/03/evolution-of-apple-pcsc-lite-from.html), that mitigated at least some of the underlying bugs.
  * OS X 10.6 "Snow Leopard" was the last version to make available the source components required for building a *tokend* (bundled into the [build folder](https://github.com/OpenSC/OpenSC.tokend/tree/master/build) for convenience).
  * Since OS X 10.7 "Lion" Apple stopped distributing *tokend*-s with the operating system [[3]](http://ludovicrousseau.blogspot.com/2011/08/mac-os-x-lion-and-tokend.html) and also deprecated CDSA (what *tokend* is built upon) as well as OpenSSL [[4]](http://ludovicrousseau.blogspot.com/2011/08/mac-os-x-lion-and-openssl.html) (what OpenSC uses for software crypto operations).
  * In OS X 10.8 "Mountain Lion" and OS X 10.9 "Mavericks" Apple made smaller changes to the underlying PC/SC and CCID subsystems but the deprecated *tokend* components still worked [[5]](http://ludovicrousseau.blogspot.com/2013/10/os-x-mavericks-and-smart-cards-status.html), [[6]](http://ludovicrousseau.blogspot.com/2012/08/mac-os-x-mountain-lion-and-smart-card.html).
  * In OS X 10.10 "Yosemite" the *tokend* codebase (mostly from 2005..2008!) required for building OpenSC.tokend still work, despite the fact that dependant components have not been updated for years and even the system C++ compiler has changed. The overall experience on 10.10 is somewhat unstable due to the rewrite of underlying smart card infrastructure, related to swapping pcscd for a CryptoTokenKit daemon [[7]](http://ludovicrousseau.blogspot.com/2014/07/os-x-yosemite-beta-and-smart-cards.html). There is no public information available on how to create a CryptoTokenKit-compatible smart card driver (could be because of shared code and one year long vendor lock of ApplePay on iOS [[8]](http://www.cnet.com/news/apple-locks-down-iphone-6-nfc-to-apple-pay/)?).


## Installation

OpenSC.tokend is distributed with the OpenSC installer for OS X and not available separately.

## Building

Building OpenSC.tokend requires the source code of OpenSC to be present. OpenSC build scripts for OS X also build the *tokend*. Minimal instructions are available in [build script source code](https://github.com/OpenSC/OpenSC/blob/master/MacOSX/build-package.in#L2).


## License

Code from OpenSC is licensed under LGPL 2.1+, components from Apple are APSL 2.0.


## Future

The whole *tokend* system is a relict from the past and destined for extinction in near future, yet it is still useful with the latest OS X versions and it is not known when Apple will pull the plug. Something new along the lines of a CryptoTokenKit plugin will probably be necessary in the future, but there are no details, roadmap or other documentation publicly available (this will hopefully change at some point). Meanwhile, for developing crypto-oriented applications, PKCS#11 is a usable (but far from best) choice for accessing smart cards in a standard way.


Regards,

@martinpaljak

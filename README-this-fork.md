### OpenSC.tokend supporting RSA and ECC tokens, with SHA-2 support
This Tokend fork provides:
* Full support of RSA tokens - signing and decrypting, including use of SHA-2 family
* Support of ECC tokens - signing, including use of SHA-2 family (no ECDH yet)

As far as we know, it provides support for all RSA and ECC PIV tokens, to the full extent of the applications' ability to use them.

One remaining problem we're aware of - support for ECC key derivation on the token - has not been addressed yet, mainly because there is no application that we know of that can use ECDH, and that we could test against. I'm planning to add ECDH support in the (near?) future, but again - the likelihood of it being useful is low, because there's nothing that can use it, as far as we know.

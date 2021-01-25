* ECDSA: (v, r, s), what is v?

The (r, s) is the normal output of an ECDSA signature, where r is computed as the X coordinate of a point R, modulo the curve order n.

In Bitcoin, for message signatures, we use a trick called public key recovery. The fact is that if you have the full R point (not just its X coordinate) and s, and a message, you can compute for which public key this would be a valid signature. What this allows is to 'verify' a message with an address, without needing to know the full key (we just do public key recovery on the signature, and then hash the recovered key and compare it with the address).

However, this means we need the full R coordinates. There can be up to 4 different points with a given "X coordinate modulo n". (2 because each X coordinate has two possible Y coordinates, and 2 because r+n may still be a valid X coordinate). That number between 0 and 3 we call the recovery id, or recid. Therefore, we return an extra byte, which also functions as a header byte, by using 27+recid (for uncompressed recovered pubkeys) or 31+recid (for compressed recovered pubkeys).

Strictly speaking the recid is not necessary, as we can just cycle through all the possible coordinate pairs and check if any of them match the signature. The recid just speeds up this verification.

In general, if h is the cofactor, the maximum number of different points with given "X coordinate modulo n" will be 2(h+1). In the case of secp256k1, which has cofactor 1, we get 2(1+1) = 4.

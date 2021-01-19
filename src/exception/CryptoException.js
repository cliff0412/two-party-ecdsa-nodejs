"use strict";
exports.__esModule = true;
exports.CryptoException = void 0;
var CryptoException = /** @class */ (function () {
    function CryptoException() {
    }
    /**
     * error types
     */
    CryptoException.UNSPECIFIED = "unspecified error";
    /**
     * general
     */
    CryptoException.NULL_INPUT = "the input is null";
    CryptoException.PARAMETER_OUT_OF_RANGE = "parameter out of range";
    CryptoException.PARAMETER_TOO_SMALL = "parameter too small";
    CryptoException.PARAMETER_TOO_LARGE = "parameter too large";
    CryptoException.INVALID_LENGTH = "invalid length";
    CryptoException.INCONSISTENT_INPUTS = "inconsistent inputs";
    /**
     * proof and commitment
     */
    CryptoException.VERIFY_PROOF_FAILED = "proof verification failed";
    CryptoException.VERIFY_COMMITMENT_FAILED = "commitment verification failed";
    CryptoException.VERIFY_PAILLIER_PUBLIC_KEY_FAILED = "Paillier public key verification failed";
    CryptoException.VERIFY_SIGNATURE_FAILED = "signature verification failed";
    /**
     * elliptic curve and point
     */
    CryptoException.UNSUPPORTED_EC_PARAMETER = "unsupported elliptic curve parameter";
    CryptoException.INFINITY_POINT = "infinity point";
    /**
     * Paillier
     */
    CryptoException.INVALID_PAILLIER_PRIVATE_KEY = "invalid Paillier private key";
    CryptoException.INVALID_PAILLIER_PUBLIC_KEY = "invalid Paillier public key";
    CryptoException.BIT_LENGTH_TOO_SMALL = "bit-length too small";
    CryptoException.PARAMETER_IS_NOT_PRIME = "parameter is not prime";
    CryptoException.SAME_PRIMES = "the primes are the same";
    CryptoException.INVALID_RANDOMNESS = "invalid randomness";
    return CryptoException;
}());
exports.CryptoException = CryptoException;

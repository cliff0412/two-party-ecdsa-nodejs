export class CryptoException {
    /**
     * error types
     */
    public static UNSPECIFIED: string = "unspecified error";

    /**
     * general
     */
    public static NULL_INPUT: string = "the input is null";
    public static PARAMETER_OUT_OF_RANGE: string = "parameter out of range";
    public static PARAMETER_TOO_SMALL: string = "parameter too small";
    public static PARAMETER_TOO_LARGE: string = "parameter too large";
    public static INVALID_LENGTH: string = "invalid length";
    public static INCONSISTENT_INPUTS: string = "inconsistent inputs";

    /**
     * proof and commitment
     */
    public static VERIFY_PROOF_FAILED: string = "proof verification failed";
    public static VERIFY_COMMITMENT_FAILED: string = "commitment verification failed";
    public static VERIFY_PAILLIER_PUBLIC_KEY_FAILED: string = "Paillier public key verification failed";
    public static VERIFY_SIGNATURE_FAILED: string = "signature verification failed";

    /**
     * elliptic curve and point
     */
    public static UNSUPPORTED_EC_PARAMETER: string = "unsupported elliptic curve parameter";
    public static INFINITY_POINT: string = "infinity point";

    /**
     * Paillier
     */
    public static INVALID_PAILLIER_PRIVATE_KEY: string = "invalid Paillier private key";
    public static INVALID_PAILLIER_PUBLIC_KEY: string = "invalid Paillier public key";
    public static BIT_LENGTH_TOO_SMALL: string = "bit-length too small";
    public static PARAMETER_IS_NOT_PRIME: string = "parameter is not prime";
    public static SAME_PRIMES: string = "the primes are the same";
    public static INVALID_RANDOMNESS: string = "invalid randomness";
}

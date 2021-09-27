export class CryptoException {
  /**
   * error types
   */
  public static UNSPECIFIED = 'unspecified error';

  /**
   * general
   */
  public static NULL_INPUT = 'the input is null';
  public static PARAMETER_OUT_OF_RANGE = 'parameter out of range';
  public static PARAMETER_TOO_SMALL = 'parameter too small';
  public static PARAMETER_TOO_LARGE = 'parameter too large';
  public static INVALID_LENGTH = 'invalid length';
  public static INCONSISTENT_INPUTS = 'inconsistent inputs';

  /**
   * proof and commitment
   */
  public static VERIFY_PROOF_FAILED = 'proof verification failed';
  public static VERIFY_COMMITMENT_FAILED = 'commitment verification failed';
  public static VERIFY_PAILLIER_PUBLIC_KEY_FAILED =
    'Paillier public key verification failed';
  public static VERIFY_SIGNATURE_FAILED = 'signature verification failed';

  /**
   * elliptic curve and point
   */
  public static UNSUPPORTED_EC_PARAMETER =
    'unsupported elliptic curve parameter';
  public static INFINITY_POINT = 'infinity point';

  /**
   * Paillier
   */
  public static INVALID_PAILLIER_PRIVATE_KEY = 'invalid Paillier private key';
  public static INVALID_PAILLIER_PUBLIC_KEY = 'invalid Paillier public key';
  public static BIT_LENGTH_TOO_SMALL = 'bit-length too small';
  public static PARAMETER_IS_NOT_PRIME = 'parameter is not prime';
  public static SAME_PRIMES = 'the primes are the same';
  public static INVALID_RANDOMNESS = 'invalid randomness';

  /**
   * BN
   */
  public static RED_POW_ERROR = 'redPow error';
}

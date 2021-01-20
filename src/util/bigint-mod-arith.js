/**
 * Returns the bitlength of a number
 *
 * @param {number|bigint} a
 * @returns {number} - the bit length
 */
function bitLength(a) {
    a = BigInt(a)
    if (a === 1n) { return 1 }
    let bits = 1
    do {
        bits++
    } while ((a >>= 1n) > 1n)
    return bits
}

/**
 * Modular exponentiation b**e mod n. Currently using the right-to-left binary method
 *
 * @param {number|bigint} b base
 * @param {number|bigint} e exponent
 * @param {number|bigint} n modulo
 *
 * @returns {bigint} b**e mod n
 */
function modPow (b, e, n) {
    n = BigInt(n)
    if (n === 0n) { throw new RangeError('n must be > 0') } else if (n === 1n) { return BigInt(0) }
  
    b = toZn(b, n)
  
    e = BigInt(e)
    if (e < 0n) {
      return modInv(modPow(b, abs(e), n), n)
    }
  
    let r = 1n
    while (e > 0) {
      if ((e % 2n) === 1n) {
        r = (r * b) % n
      }
      e = e / 2n
      b = b ** 2n % n
    }
    return r
  }

  /**
 * Finds the smallest positive element that is congruent to a in modulo n
 * @param {number|bigint} a An integer
 * @param {number|bigint} n The modulo
 *
 * @returns {bigint} The smallest positive representation of a in modulo n
 */
 function toZn (a, n) {
    n = BigInt(n)
    if (n <= 0) { return NaN }
  
    a = BigInt(a) % n
    return (a < 0) ? a + n : a
  }
module.exports ={
    modPow,
    bitLength,
    toZn
} ;
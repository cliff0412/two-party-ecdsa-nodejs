import BN from 'bn.js'
import * as bigintConversion from 'bigint-conversion'
import * as bigintModArith from 'bigint-mod-arith'
import { bnFromHexString } from './desearilization'

/**
 * TODO: try to improve this and do not use external libraries
 * @param bn 
 * @param N modulus
 * @returns 
 */
export const modInverse = (bn: BN, N: BN): BN => {

    const resBigInt = bigintModArith.modInv(
        bigintConversion.bufToBigint(bn.toBuffer()),
        bigintConversion.bufToBigint(N.toBuffer())
    )
    return bnFromHexString(bigintConversion.bigintToHex(resBigInt))
}

/**
 * TODO: try to improve this and do not use external libraries
 * @param base 
 * @param exponent 
 * @param N 
 * @returns 
 */
export const modPow = (base: BN, exponent: BN, N: BN): BN => {
    const resBigInt = bigintModArith.modPow(
        bigintConversion.bufToBigint(base.toBuffer()),
        bigintConversion.bufToBigint(exponent.toBuffer()),
        bigintConversion.bufToBigint(N.toBuffer())
    )
    return bnFromHexString(bigintConversion.bigintToHex(resBigInt))
}
import BN from 'bn.js'
import * as bigintConversion from 'bigint-conversion'
import * as bigintModArith from 'bigint-mod-arith'
import { bnFromHexString } from './desearilization'

/**
 * 
 * @param bn 
 * @param N modulus
 * @returns 
 */
export const modInverse = (bn: BN, N: BN): BN => {
    // while(bn.gt(N)) {
    //     console.log("sub......")
    //     bn = bn.sub(N)
    // }
    // const bnInRed = bn.toRed(BN.red(N));
    // return bnInRed.redInvm();


    const resBigInt = bigintModArith.modInv(
        bigintConversion.bufToBigint(bn.toBuffer()),
        bigintConversion.bufToBigint(N.toBuffer())
    )
    return bnFromHexString(bigintConversion.bigintToHex(resBigInt))
}
// import BN from 'bn.js';

// class Random {

//     public static ZERO = new BN(0);
//     public static MAX_ITERATIONS = 1000;

//     public static createRandomInRange(min: BN, max: BN): BNN {


//         if (min.gt(max)) {
//             throw new Error("'min' may not be greater than 'max'")
//         }

//         if (min.eq(max)) return min;

//         if (min.bitLength() > max.bitLength() / 2) {
//             return this.createRandomInRange(this.ZERO, max.sub(min)).add(min);
//         }

//         for (let i = 0; i < this.MAX_ITERATIONS; ++i) {
//             BigInteger x = createRandomBigInteger(max.bitLength(), random);
//             if (x.compareTo(min) >= 0 && x.compareTo(max) <= 0) {
//                 return x;
//             }
//         }

//         // fall back to a faster (restricted) method
//         return createRandomBigInteger(max.subtract(min).bitLength() - 1, random).add(min);
//     }

//     public static createRandomBigInteger(bitLength: number): BN {
//         return new BigInteger(1, createRandom(bitLength, random));
//     }

//     private static createRandom( bitLength: number)
         
//         {
//             if (bitLength < 1) {
//                 throw new Error("bitLength must be at least 1");
//             }

//             let nBytes = (bitLength + 7) / 8;

//             byte[] rv = new byte[nBytes];

//             random.nextBytes(rv);

//             // strip off any excess bits in the MSB
//             int xBits = 8 * nBytes - bitLength;
//             rv[0] &= (byte)(255 >>> xBits);

//             return rv;
//         }
// }


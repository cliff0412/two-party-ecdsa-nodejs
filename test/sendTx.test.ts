import BN from 'bn.js'

import {sendTx} from '../src/chain/chain'

import {
    SigningContextP1,
    SigningContextP2,
    KeyGenContextVO,
    PaillierPrivateKey,
    PaillierPublicKey,
} from '../src'


import {
    CryptoConsants
} from '../src/common/CryptoConstants';


test("sendTx", async () => {
    let keyGenCtx: KeyGenContextVO = {
        "addressFromPoint": "0x7e3D67bab611E25b4Fc9D31C0aEe20cc852e40DF",
        "addressFromX": "0x7e3D67bab611E25b4Fc9D31C0aEe20cc852e40DF",
        "x": "af82ad81d61763e45dda07091ebc903a2c8cecf9fe2f8404df60abf2c2ffc8ae",
        "p1": {
            "x1": "deb881f5fd4c35a231ad6b438d43e62f7031d9b80d6ead95f297e517241ca5e",
            "paillierPrivateKeyP": "d3a94cc7ce9cc1b8a9f785770f047c422b8be17877cc68ece2a8e02cf4db7822a1a0f39953cd36eb64ac2b1a20f2e0174ea327738b4d6fc05cce1700cbabfc08c89e7a49ae3ca5cbef747a47e06314f9756dba0d314d506c32564434f5d98be9f59cfc7e3503235c682cd542c304c8a83d7018367e6464c2376f59dfe8022495",
            "paillierPrivateKeyQ": "dcb58bf25f5ea25e1d1a9b1cc2d73d65942bfc955030488669a854f7c94fbec00aa4b6ed1d5193483d1bcbe41c4df45d81d912ff71db378404a12b5781e31ebda58440cd8a3c35ab32c7e4719345e127db92ea819645bf85120bd1a1bcf62bf10c9016ab8bcdfffec2d7522bf2c7a0372f63da37ca41384a295d52dcb69476ab"
        },
        "p2": {
            "paillierPublicKeyN": "b67b98645068ef4760da2041305ce962e9f9ad621c84503c4439ecec38f19c0db3809926337f71821454775a433a770d15d537103913f85c64a7d3cfe84059d9e033fc9c279cdb6d276271157ff9b95abee27608a773c84c935a7e4b9038c8ddb95be8e4c6048cc524e0249f6b84612940b6673ff4e055828689cd2970fb66b67eada6571e314cf62089fc6fc84c28deb14155d7ea70444a8c5236d2d23f20667bda75d54f0d0545eb03a9176059dd9f455f6a01f9287e1d2cd9b740a27b2ab9aedbe87ab761cfd373ca41384bbbfaedc18914680d534410e10b42d48243a9b67fd6dd09acd0be76fd6f9d0ab5a8ad53fb61cebc3ca0c9feb7e20ecc0a6f1d87",
            "cKey": "240b53989689f4b984746e376cad7c95ee7603ccb3f7d6ef8a0603d63581f0835e867096a01b449a078e3b8549e7c8edee5b233a3f0e6763a3ac205176cc6520de4bb5dd97c638a2d45def7789dadba94e69f3dbdcaade6b38c66794ea18bb2551ed90e7895be962b06fc625ef33d5b28d0b1dc25f0b7b6af34b2114f4f617ca79bc59ebdac75639186ccd2208788887ea310a1764a793bdff61a143d2de8da4fef80852fe310fc526e890061277c4aca459b1f7251cb8158b884f0938b8e16fa20c73756a1c684c85b8201853a8bd84f14245d5e04ea541c2eb2ea1d9e81f387118dcae1e33a5b0bdbf4a09f21498134ffe2a7ab202da2c67f0faaab10dfe4739c58da8b5bd8588040fdb9f71fa5a8db8c4b76efe5a59394527ad68abaa49d6734024e05e94b30a667e401c5ab6c18a3a36c7a09afd5d7c4ff6c1457ae4a8765d61bc1289327ffc18ed0ce1f54fc2cb0ddf1735faeb4e3bc9bfc63b0841e4fa642b1b8c851096314224ec0c2898c63c285eab2c8e8e2b10fa760d2429a5efb3f28044c59fa76ac8fe700882d62cd3a09a3d65a9484fee9414be763c7efb42a67d0772efa828103e0bb21b8735731ec19d6979318ced763dfc44744859623df50965cac92d8a9cce9a1898a545b153a0c06e9a0dbdb5fe3017f88a87e656b366d5d99996425e2cce66a1f3494e13d626e89fb953bbb6e82a854d762cf4c8e5f1",
            "x2": "18492c2f59f3e088279caddeedbe07898d24101eabfeb50bb841089e201fb422"
        }
    }
    let x1 = new BN(keyGenCtx.p1.x1, "hex");
    let x2 = new BN(keyGenCtx.p2.x2, "hex");
    let x = x1.mul(x2).mod(CryptoConsants.SECP256_CURVE_N);
    let Q = CryptoConsants.SECP256_CURVE_G.mul(x)
    let signingContextP1 = new SigningContextP1(
        new PaillierPrivateKey(
            new BN(keyGenCtx.p1.paillierPrivateKeyP, "hex"),
            new BN(keyGenCtx.p1.paillierPrivateKeyQ, "hex")),
        x1,
        Q
    )

    let signingContextP2 = new SigningContextP2(
        new PaillierPublicKey(new BN(keyGenCtx.p2.paillierPublicKeyN, "hex")),
        new BN(keyGenCtx.p2.cKey, "hex"),
        x2,
        Q
    )
    let to = "0x11B73358799D057D195fCeC8B93C70E54E39da27"
    await sendTx(
        keyGenCtx.addressFromX,
        to,
        signingContextP1,
        signingContextP2
    )


    setInterval(() => console.log("wait"), 10000)

})




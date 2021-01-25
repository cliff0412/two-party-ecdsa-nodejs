import BN from 'bn.js'
import { recover } from './chain'

import {
    Signature,
} from '../type'

test('recover', () => {

    let sig: Signature = {
        r: new BN("cd5b4df362ec396321a8863eca3632083c471c34001a3ff6ae8cedf15b6d5ae0", "hex"),
        s: new BN("610b48de9afcd4d16f41dfc1e74d15010c8e4d4de9b56eeb6ec713107362e295", "hex"),
        recovery: 1
    }
    let address = recover(
        Buffer.from("a0add5f0f71f738a8d8b9e5bf8f874c48b04690957432586d17d82e5735a91ea", "hex"),
        sig
    )
    expect(address).toBe('0x7e3D67bab611E25b4Fc9D31C0aEe20cc852e40DF')
})
import { BigNumber } from '@ethersproject/bignumber';
import { keyGen } from './fixture/two-party-ecdsa';
import { signTransaction } from './fixture/signer';
import Ganache from './ganache';
import { KeyGenContextVO } from '../src';

describe('e2e test two party ecdsa', () => {

    const [fauceter, receiver] = Ganache.signers;
    let keyGenInfo: KeyGenContextVO;
    beforeAll(async () => {
        keyGenInfo = await keyGen()
        await fauceter.sendTransaction({
            to: keyGenInfo.addressFromPoint,
            value: BigNumber.from(10).pow(18)
        })
    })

    it("send tx to ganache", async () => {

        const receiverAddress = await receiver.getAddress();

        const balanceOfReceiverBefore = await Ganache.provider.getBalance(
            receiverAddress,
        );
        const tx = {
            to: await receiver.getAddress(),
            value: BigNumber.from(10),
        };

        const signedTx = await signTransaction(tx, keyGenInfo);

        const txSent = await Ganache.provider.sendTransaction(signedTx);
        const receipt = await txSent.wait();
        const balanceOfReceiverAfter = await Ganache.provider.getBalance(
            receiverAddress,
        );

        expect(receipt.status).toBe(1);
        expect(
            balanceOfReceiverAfter.sub(balanceOfReceiverBefore).toNumber(),
        ).toEqual(10)


    })
})





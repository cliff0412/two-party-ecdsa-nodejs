import BN from 'bn.js';
import * as random from './random';

test('randomPrime', async ()=> {
    random.randomPrime(2048).then(res => console.log(res.toString()));

})


test('randBetween', () => {

    let min= new BN("3");
    let max = new BN("100000")
    let res = random.randBetween( min, max)
    expect(res.gte(min) && res.lte(max)).toBeTruthy();
})
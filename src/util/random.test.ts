import * as random from './random';

test('randomPrime', async ()=> {
    random.randomPrime(2048).then(res => console.log(res.toString()));

})
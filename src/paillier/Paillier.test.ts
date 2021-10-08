import '@babel/polyfill';

import BN from 'bn.js';
import {PaillierPublicKey} from './PaillierPublicKey';
import {Paillier} from './Paillier';
import PaillierKeyPairGenerator from './PaillierKeyPairGenerator';
import {PaillierKeyPair} from './PaillierKeyPair';

// test('encrypt', async () => {

//     let n = new BN("22499561804813614971904627727600372060465575339602988178504692591064284157762209618231066333752771304510284490257629722725693330004592355063919101039144207339866852995634696558639760056207391990755910471671615384137094765218144924297340645434461473248356233279465523496592952150631358207970571334766323177765891800214783401379679071214609769593746888434669898509768788604774174692670703455763406706953367461375844432337537132241254009526669380786248175067625373104772707756832622542620598685827227876865921482777923761411030910101108076118309999828002987912197677081729953609306990701320633852662635630556217616610713", 10);

//     let pubKey = new PaillierPublicKey(
//         n
//     );

//     let res = Paillier.encrypt(pubKey, new BN("123456789"));
//     // console.log(res.toString());
// })

test('encryptWithRandom', () => {
    let n = new BN("22499561804813614971904627727600372060465575339602988178504692591064284157762209618231066333752771304510284490257629722725693330004592355063919101039144207339866852995634696558639760056207391990755910471671615384137094765218144924297340645434461473248356233279465523496592952150631358207970571334766323177765891800214783401379679071214609769593746888434669898509768788604774174692670703455763406706953367461375844432337537132241254009526669380786248175067625373104772707756832622542620598685827227876865921482777923761411030910101108076118309999828002987912197677081729953609306990701320633852662635630556217616610713", 10);

    let pubKey = new PaillierPublicKey(
        n
    );
    let res = Paillier.encryptWithRandom(pubKey, new BN("123456789"), new BN("13"))

    let expectedOut = "334724493050638358175350221271250100086860406134610598514870162922400358803394674294047652738700027193925769193956270089629089959954572344000793532762243322923298634386396456716144572939436469006013787141574268026735662870032014164175504759103363547025162292080350271356759117825951940564443118390451032404834164035406849237099896366104722150083535066699946126735623213544065962639438845329441425503467495229718630510003481062975865292924898773592547844801205436436109128376071973036791146680184850553545323426620103616848461547710664970727879644349312667680638531429476551451020111942227961087384385514376574950410917672428576989931471090307330082270301474357843230560731184552296283245441512304462622143471795120131245059158223871105056066390029196350967204865264264204541297718265483502421311688240699533266693289816081453522209333520218949525996005284906970948003455991895077212052145934185803073883249980832304165363515923025894710041190171219964593678052472457728031536654222802177411704757135208276696025811729103989385343111357475939207098991713200027697267814838905961871222791873585002065461321913998845366889643195470529131465369118758392118659130571290777317100032162224966658158370729183478374343948256133069870376291695"
    expect(res.toString()).toBe(expectedOut);
})

test('decrypt', async () => {


    let paillierKeyPairGenerator: PaillierKeyPairGenerator = new PaillierKeyPairGenerator(2048);

    let keyPair: PaillierKeyPair = await paillierKeyPairGenerator.generateKeyPair();

    let m = new BN("1234567890", 10);
    let r = new BN("13", 10);

    let c: BN = Paillier.encryptWithRandom(keyPair.getPublicKey(), m, r);

    let res = Paillier.decrypt(keyPair.getPrivateKey(), c);
    // console.log(res.toString());
    expect(res.toString()).toBe(m.toString());
})

test('add', () => {

    let n = new BN("22499561804813614971904627727600372060465575339602988178504692591064284157762209618231066333752771304510284490257629722725693330004592355063919101039144207339866852995634696558639760056207391990755910471671615384137094765218144924297340645434461473248356233279465523496592952150631358207970571334766323177765891800214783401379679071214609769593746888434669898509768788604774174692670703455763406706953367461375844432337537132241254009526669380786248175067625373104772707756832622542620598685827227876865921482777923761411030910101108076118309999828002987912197677081729953609306990701320633852662635630556217616610713", 10);

    let pubKey = new PaillierPublicKey(
        n
    );

    let m1 = new BN("1234567890", 10);
    let r1 = new BN("13", 10);


    let m2 = new BN("1234567891", 10);
    let r2 = new BN("7", 10);


    let c1: BN = Paillier.encryptWithRandom(pubKey, m1, r1);
    let c2: BN = Paillier.encryptWithRandom(pubKey, m2, r2);
    let res = Paillier.add(pubKey, c1, c2)

    let expected = "15679381670925322265452988034246086902937410676639641838775068595438425912323472875927268968616776410024860070432391119934304289886662613817449058964564225650489394182622898831152857259699754770083957874450798396400389573978030904661439162039674686703753210971734140393117095124222954772244269587127583656516544461635077109383950283173439914810918103934078271484444652186533883645980422598347969964665509281708980334044999374360230823742348777657582562831142270510830809161520160144658892667546919485501648023148447017871620421495871040834902053859078837449475694004220346124833608184696003802941254135317493912596090343663254138295722681174241873895430207917542493711075382596766568350291621595790397470380288454720080020189930635640573265560835698299092789569722032002385165374713723510765657100817044142906454833185705448358035687919350390738877181386357365076513294467220717190949337555731438781411339774074225464599798968961326381661035326333599440864127736491649452440045628264166333391419071467849759922647216262253053930195496277751566866877048689667026822491388106588774322232389121032658508237809158817055883355498681444895702670820673650208407272341437569050708717618688967339548589976118389668294468174111157157098976545"
    // console.log(res.toString());
    expect(res.toString()).toBe(expected);
});

test('subtract', () => {
    let n = new BN("22499561804813614971904627727600372060465575339602988178504692591064284157762209618231066333752771304510284490257629722725693330004592355063919101039144207339866852995634696558639760056207391990755910471671615384137094765218144924297340645434461473248356233279465523496592952150631358207970571334766323177765891800214783401379679071214609769593746888434669898509768788604774174692670703455763406706953367461375844432337537132241254009526669380786248175067625373104772707756832622542620598685827227876865921482777923761411030910101108076118309999828002987912197677081729953609306990701320633852662635630556217616610713", 10);

    let pubKey = new PaillierPublicKey(
        n
    );

    let m1 = new BN("1234567890", 10);
    let r1 = new BN("13", 10);


    let m2 = new BN("1234567891", 10);
    let r2 = new BN("7", 10);


    let c1: BN = Paillier.encryptWithRandom(pubKey, m1, r1);
    let c2: BN = Paillier.encryptWithRandom(pubKey, m2, r2);
    let res = Paillier.subtract(pubKey, c1, c2)

    let expected = "144834510047795495423670486617719615973559127690717287580488330990567863452759212240579320629441742384366941364660106587479149037973785411300784611547567052830913780130972808351580123266914073903927901187372492944383574417607918205373962354418674293941128785015632986289879774701964084243694494841417522579204582796595090611811860852728961016593778761529067407689892214112377482625199640725759485409321414039095021915114047026877189754968734546138792533628697856195533005411215909965343045453220993477240517445500890240344774377546374959606122877574335730179332975718410282778343410449993920728114842879793206319031567206439270071862566064517225482650881199277456185999231335947517847527140479369056211292051189500516437511914440147390374570913713197328533575804080335213884186790154434190141841101060263807036740446699914597793315911191514522297852189769266177661515570412428813201628217131840470679647760081155917167694735912491222274287885189995252779164005779873196527536541024056788165159291718682520427928750490759076365618986413006056015565023585676871010428499416982063641187665953871661689502471704755626778795867317790517055041064925082472256252716676811717481823016019544022721083017365822331902934353236871815007241508505"
    // console.log(res.toString());
    expect(res.toString()).toBe(expected);
});

test('subtractPlain', () => {

    let n = new BN("22499561804813614971904627727600372060465575339602988178504692591064284157762209618231066333752771304510284490257629722725693330004592355063919101039144207339866852995634696558639760056207391990755910471671615384137094765218144924297340645434461473248356233279465523496592952150631358207970571334766323177765891800214783401379679071214609769593746888434669898509768788604774174692670703455763406706953367461375844432337537132241254009526669380786248175067625373104772707756832622542620598685827227876865921482777923761411030910101108076118309999828002987912197677081729953609306990701320633852662635630556217616610713", 10);

    let pubKey = new PaillierPublicKey(
        n
    );

    let m1 = new BN("1234567890", 10);
    let r1 = new BN("13", 10);
    let c1: BN = Paillier.encryptWithRandom(pubKey, m1, r1);

    let m2 = new BN("1234567891", 10);

    let res = Paillier.subtractPlain(pubKey, c1, m2);
    // console.log(res.toString())

    let expected = "161385681615619391989244871038857409499508991591223300106918082948760970000110278019432107382611250087959134133321832943793355938850451179642526120638268624785862081243991676784859524186150012141274928249053766767126336483904090122930460589576482852799891003761377486101740549476546001942834252651546670739005325270196497300854319161793609241648759654421985767637291460996962241252120044224748337330309601003483661882929114378243971311702694720369423496606494844867980870600352295555746028503571929871687075769415764148475205112691351440735304703034617522702283535251376220416796639886799703420881901237987168851706361468526673830496009808221642773082861878517561199296634907940538056637456655833532369794098263023618048241020429761694983357036807675563316063293439870235624283666421480859703279911890997543909080426927656296654699820078924767844699159414601987713084963033401828669455015159544977589676621543937065073191801698897637805930421132654779499015627755331553038110954795923886573010606233984409139169049774451624190317036997500390001996327213625630614831631840761172760244410516954707707040227591629542751315788963118271213239632493017163602823969205525178443258767594499411652411247999002966653485809256450979671521412305"
    expect(res.toString()).toBe(expected);

})

test('multiply', () => {
    let n = new BN("22499561804813614971904627727600372060465575339602988178504692591064284157762209618231066333752771304510284490257629722725693330004592355063919101039144207339866852995634696558639760056207391990755910471671615384137094765218144924297340645434461473248356233279465523496592952150631358207970571334766323177765891800214783401379679071214609769593746888434669898509768788604774174692670703455763406706953367461375844432337537132241254009526669380786248175067625373104772707756832622542620598685827227876865921482777923761411030910101108076118309999828002987912197677081729953609306990701320633852662635630556217616610713", 10);

    let pubKey = new PaillierPublicKey(
        n
    );

    let m1 = new BN("1234567890", 10);
    let r1 = new BN("13", 10);
    let c1: BN = Paillier.encryptWithRandom(pubKey, m1, r1);

    let m2 = new BN("1234567891", 10);

    let res = Paillier.multiply(pubKey, c1, m2);
    // console.log("multiply out: ",res.toString())

    let expected = "315758449313406916160133010576427507211194065120727787993093545214739472386613864801556505623432627712542265514711697796223106986386580165660970619833356702289245783790792629398916028200089840588357247656507140196264813409418072554718381127972692157500867668835624082339163434152126124879327015377012084426849941715152233504805170167873293640132722587343277613680356182272620443691936005369542111068726912848570721555712678341262751747121668449528695145176152019788269827372881205683091327717740585442734062844919335723599910373248701114702120160623761444385596686109194948456603414903935180272757543664135718756310070538763609369292688459046983614681430505662030146603015656322759367717468365826922116078439915118432923088802343457435703396183640613327552359930598832659584407136214530008212956738988233790004180468889414959634841816491717845178259703597461064314063818748414868267937156532824062273913309039421048557632751975457540480288701230771270610182316292226167217998877250091898730438512042590967829026807765108858224857052539957777396030897568379177461670638784371593742192824563950074428829745222819604826666077498510154673532518299520758096392183296014917739566307480565642403942455957691117355494889412023339718530641424"
    expect(res.toString()).toBe(expected);

});
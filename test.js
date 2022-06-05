/**
   Locally test with a confirmation, eg. 0x3 claim confirmed by 0x6 which can be seen by 0x4

   This depends on endorser-ch:
   - test/test.sh
   - cp ../endorser-ch-test-local.sqlite3 ../endorser-ch-dev.sqlite3
   - echo "select id, subject from jwt where claimType = 'Organization';" | sqlite3 ../endorser-ch-dev.sqlite3
   - NODE_ENV=dev npm run dev
   - ... and then add the 0x3 claim to TEST_CLAIM below

   Some of this is copied in the endorser-ch repo (eg. test/util.js).
**/

const { Credentials } = require('uport-credentials')

const auth = require('./index').auth

const ENDORSER_SERVER='http://localhost:3000'
const TEST_CLAIM='01G4S0Z0AE42V7ZVHJ0C82J262'

const config = {
  // owner is the account running this test, who should have access to see the people in the claims & confirmations
  ownerDid: 'did:ethr:0x2224EA786b7C2A8E5782E16020F2f415Dce6bFa7',

  // key for the owner, used to access the claims
  ownerPrivateKeyHex: '1c9686218830e75f4c032f42005a99b424e820c5094c721b17e5ccb253f001e4',

  // account who is trusted to confirm the claim
  confirmerDid: 'did:ethr:0x666fb9f5AE22cB932493a4FFF1537c2420E0a4D3',

  // name of organization in question
  orgName: 'Cottonwood Cryptography Club',

  // name of role inside organization for access
  orgRoleName: 'President',
}

const vp = {
  "iat": 1654469929,
  "verifiableCredential": [
    {
      "iat": 1654469929,
      "credentialSubject": {
        "@context": "https://schema.org",
        "@type": "Organization",
        "member": {
          "@type": "OrganizationRole",
          "member": {
            "@type": "Person",
            "identifier": "did:ethr:0x3334FE5a696151dc4D0D03Ff3FbAa2B60568E06a"
          },
          "roleName": "President",
          "startDate": "2019-04-01"
        },
        "name": "Cottonwood Cryptography Club"
      },
      "issuer": {
        "id": "did:ethr:0x3334FE5a696151dc4D0D03Ff3FbAa2B60568E06a"
      },
      "id": "http://127.0.0.1:3000/api/claim/01G4S0Z0AE42V7ZVHJ0C82J262",
      "type": [
        "VerifiableCredential"
      ],
      "@context": [
        "https://www.w3.org/2018/credentials/v1"
      ],
      "issuanceDate": "2022-06-05T22:58:49.000Z",
      "expirationDate": "2122-05-12T22:58:49.000Z",
      "proof": {
        "type": "JwtProof2020",
        "jwt": "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2NTQ0Njk5MjksInZjIjp7ImNyZWRlbnRpYWxTdWJqZWN0Ijp7IkBjb250ZXh0IjoiaHR0cHM6Ly9zY2hlbWEub3JnIiwiQHR5cGUiOiJPcmdhbml6YXRpb24iLCJtZW1iZXIiOnsiQHR5cGUiOiJPcmdhbml6YXRpb25Sb2xlIiwibWVtYmVyIjp7IkB0eXBlIjoiUGVyc29uIiwiaWRlbnRpZmllciI6ImRpZDpldGhyOjB4MzMzNEZFNWE2OTYxNTFkYzREMEQwM0ZmM0ZiQWEyQjYwNTY4RTA2YSJ9LCJyb2xlTmFtZSI6IlByZXNpZGVudCIsInN0YXJ0RGF0ZSI6IjIwMTktMDQtMDEifSwibmFtZSI6IkNvdHRvbndvb2QgQ3J5cHRvZ3JhcGh5IENsdWIifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdfSwiZXhwIjo0ODA4MDY5OTI5LCJqdGkiOiJodHRwOi8vMTI3LjAuMC4xOjMwMDAvYXBpL2NsYWltLzAxRzRTMFowQUU0MlY3WlZISjBDODJKMjYyIiwibmJmIjoxNjU0NDY5OTI5LCJpc3MiOiJkaWQ6ZXRocjoweDMzMzRGRTVhNjk2MTUxZGM0RDBEMDNGZjNGYkFhMkI2MDU2OEUwNmEifQ.v1jZNgxKOo0hntGTyZxDbn6TWymLIhjDAZf_dRJNcKHZUOWr-k5E2rgluRZaP9OuLiT9ObVtqeLEDaCmiehBBA"
      }
    }
  ],
  "holder": "did:ethr:0x3334FE5a696151dc4D0D03Ff3FbAa2B60568E06a",
  "type": [
    "VerifiablePresentation"
  ],
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "issuanceDate": "2022-06-05T22:58:49.000Z",
  "expirationDate": "2122-05-12T22:58:49.000Z",
  "proof": {
    "type": "JwtProof2020",
    "jwt": "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2NTQ0Njk5MjksInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSkZVekkxTmtzaUxDSjBlWEFpT2lKS1YxUWlmUS5leUpwWVhRaU9qRTJOVFEwTmprNU1qa3NJblpqSWpwN0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JqYjI1MFpYaDBJam9pYUhSMGNITTZMeTl6WTJobGJXRXViM0puSWl3aVFIUjVjR1VpT2lKUGNtZGhibWw2WVhScGIyNGlMQ0p0WlcxaVpYSWlPbnNpUUhSNWNHVWlPaUpQY21kaGJtbDZZWFJwYjI1U2IyeGxJaXdpYldWdFltVnlJanA3SWtCMGVYQmxJam9pVUdWeWMyOXVJaXdpYVdSbGJuUnBabWxsY2lJNkltUnBaRHBsZEdoeU9qQjRNek16TkVaRk5XRTJPVFl4TlRGa1l6UkVNRVF3TTBabU0wWmlRV0V5UWpZd05UWTRSVEEyWVNKOUxDSnliMnhsVG1GdFpTSTZJbEJ5WlhOcFpHVnVkQ0lzSW5OMFlYSjBSR0YwWlNJNklqSXdNVGt0TURRdE1ERWlmU3dpYm1GdFpTSTZJa052ZEhSdmJuZHZiMlFnUTNKNWNIUnZaM0poY0doNUlFTnNkV0lpZlN3aVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmxaR1Z1ZEdsaGJITXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSmRmU3dpWlhod0lqbzBPREE0TURZNU9USTVMQ0pxZEdraU9pSm9kSFJ3T2k4dk1USTNMakF1TUM0eE9qTXdNREF2WVhCcEwyTnNZV2x0THpBeFJ6UlRNRm93UVVVME1sWTNXbFpJU2pCRE9ESktNall5SWl3aWJtSm1Jam94TmpVME5EWTVPVEk1TENKcGMzTWlPaUprYVdRNlpYUm9jam93ZURNek16UkdSVFZoTmprMk1UVXhaR00wUkRCRU1ETkdaak5HWWtGaE1rSTJNRFUyT0VVd05tRWlmUS52MWpaTmd4S09vMGhudEdUeVp4RGJuNlRXeW1MSWhqREFaZl9kUkpOY0tIWlVPV3ItazVFMnJnbHVSWmFQOU91TGlUOU9iVnRxZUxFRGFDbWllaEJCQSJdfSwiZXhwIjo0ODA4MDY5OTI5LCJuYmYiOjE2NTQ0Njk5MjksImlzcyI6ImRpZDpldGhyOjB4MzMzNEZFNWE2OTYxNTFkYzREMEQwM0ZmM0ZiQWEyQjYwNTY4RTA2YSJ9.jluVsUiStwzj2uWpNq4j7bRX90dXAmjsEQ9gPL_Tou84c_2WyVRfNEbo7fOZV6HOmGA8EVmgIWmqxYq6CpuUYw"
  }
}


const CREDS = [
  // those with mnemonic created by @ethersproject/hdnode: HDNode.fromMnemonic(bip39.entropyToMnemonic(crypto.randomBytes(32))).derivePath("m/7696500'/0'/0'/0'")
  // ... and the rest created by Credentials.createIdentity()

  { did: 'did:ethr:0x000Ee5654b9742f6Fe18ea970e32b97ee2247B51', privateKey: '01a3172cd9e334210b2669dce737d435beefe5c99802ded607c44cd85c96666b' }, // seminar accuse mystery assist delay law thing deal image undo guard initial shallow wrestle list fragile borrow velvet tomorrow awake explain test offer control
  { did: 'did:ethr:0x111c4aCD2B13e26137221AC86c2c23730c9A315A', privateKey: '75fc2f133b27078d4b6bf61e90d31d240f9fa7eb8edb30289264374e82c05da6' }, // average mammal spice rebuild volume border tail bracket else absent sniff connect praise tennis twice inquiry summer crawl job nurse sister account tooth follow
  { did: 'did:ethr:0x2224EA786b7C2A8E5782E16020F2f415Dce6bFa7', privateKey: '1c9686218830e75f4c032f42005a99b424e820c5094c721b17e5ccb253f001e4' }, // annual soap surround inhale island jewel blush rookie gate aerobic brave enlist bird nut remain cross undo surround year rapid blade impulse control broccoli
  { did: 'did:ethr:0x3334FE5a696151dc4D0D03Ff3FbAa2B60568E06a', privateKey: 'b53089b38411ebda74f3807b810cc28f1bd3f9d8baf4e70fe81cd4f89537bbf9' }, // story wine milk orbit that mountain bus harvest piano warm idea pigeon major gallery check limit pond people torch use labor flock type pond
  { did: 'did:ethr:0x444D276f087158212d9aA4B6c85C28b9F7994AAC', privateKey: 'e7aea73ba5b9b45136bc1bf62b7ecedcd74ae4ec87d0378aeea551c1c14b3fc5' }, // mad insect spread pluck ready surround front table ghost present credit repair rather repair lobster fragile bleak okay loud dose cruel success wash credit
  { did: 'did:ethr:0x55523607353c874D88bC7B6B6E434C4F6945F3A4', privateKey: '946a5d7e7b950b0a1e5da7f510db32f028c8f01574e47097f618dc4de5de2d1c' }, // egg stick repeat attack discover shoe below strategy occur copy wish hour belt marriage gravity common illness film then sword aerobic apology seminar border
  { did: 'did:ethr:0x666fb9f5AE22cB932493a4FFF1537c2420E0a4D3', privateKey: '5ee77cc7819803c0c3468683d15336647b16ef7967db93226ac634a5761a4678' }, // situate plate artwork math error castle knock fitness museum they list library buyer village rail screen prosper hockey bless south matter message whale arrive
  { did: 'did:ethr:0x777cd7E7761b53EFEEF01E8c7F8F0461b0a2DAdc', privateKey: 'd1e46db1bcbeef7e94f49ad2624b185e635609bea51f856fe9a2b2c44e0a04a2' }, // lonely stage long vote amateur web churn aspect neck cheese display wreck empty flock luggage number dynamic catalog soon they merit cactus naive diagram
  { did: 'did:ethr:0x888f266617cf244116362C90dA1731D6A2F1f4DD', privateKey: 'cfcba0f6e1aff4e72f3909e0168eca77e094e9635a66d3cca37c3bef4e35811c' }, // elite muscle claw steel amazing recipe addict cable tool office lava eager once whale audit wild avoid trade urge kick december draw glare sense
  { did: 'did:ethr:0x999BFe538DfC795FbcfEDe2D95C3BB3067CA3Ee3', privateKey: '82a115b095e03bd28a06fe294887d99a270145591b5d291acf80d3574a8e558f' }, // bag always embrace army fresh pretty buzz idea pear alien size property chalk hidden nothing credit pill wolf anger shrimp design glue zebra jealous
  { did: 'did:ethr:0xaaa808B42C3Cb12c6ca7110E327284028214657D', privateKey: 'e76b01b8af46082608753a907d926264e1700fc309fbef2f68380147be97ee7d' }, // grant stay suggest style antique upon scout evidence animal example live demand have erase congress hurry frequent network foot welcome struggle wave popular marble
  { did: 'did:ethr:0xbbbe0e5Af02D327d33C280855d478FFa57FBab70', privateKey: '86c72e586ceb818ab3e8bedab4a250e08dd9f0df2d483374c0c5f07452e8ba40' }, // claim brother drift deputy gaze emerge bunker vibrant game ski crucial myself attitude slush crew home crater guide second scout lonely earth chaos tunnel
  { did: 'did:ethr:0xccc0B0759Dbe2c49D3862f6F403Fae94dD905FC9', privateKey: '8a62b154e40a6a9839a8d0275d2886df05495dc2123ecabd0cb4719cd23630c4' }, // blue still absent awake casual always magnet item until undo release satoshi surface attract learn ridge security minimum grid clinic license lawn skate illness
  { did: 'did:ethr:0xddd3ef4cf2900f048b01713d50f61d232c2731ee', privateKey: '39482d2c39e9def860cf9f48facfe67a16c45209ecfba9c12bfc5bf831d80dc6' }, // wild fish nuclear scheme bamboo large solid express already rookie hire jump add announce thank spoon law pull bless cancel outside plate allow admit
  { did: 'did:ethr:0xeeeb9589823e0baef3635726006e611da7a715b9', privateKey: 'cb4ad57b266a628eb0b7ff74754d661ce036420cd1335720f53c31b5e74c268d' }, // arrest claim way idea hat wrap execute girl noble task march web capital this thrive time small erupt public tortoise violin one forest abandon
  { did: 'did:ethr:0xffff7def6267bedac4bd8bb2fa9128e8698b3d2f', privateKey: '741cc1ad98494afd4a9b9219b678e213fd5a27f6dd7822350d011430b0018e6d' }, // history loyal voice arm upper energy night interest vacuum swap siren economy siren tomorrow kick gain possible disorder scan same move wheat artefact notice
  ]

require("ethr-did-resolver").default()

const CREDENTIALS = CREDS.map((c) => new Credentials(c))
const NOW_EPOCH = Math.floor(new Date().getTime() / 1000)
const TOMORROW_EPOCH = NOW_EPOCH + (24 * 60 * 60)
const pushTokenProms = CREDENTIALS.map((c) => c.createVerification({ exp: TOMORROW_EPOCH }))

const bent = require('bent')
const assert = require('assert').strict

const twoWaySees2 = async (jwts, id) => {
  let post, result

  post = bent(ENDORSER_SERVER, 'POST', 'json', { 'Uport-Push-Token': jwts[2] })
  result = await post('/api/report/canSeeMe', { did: CREDS[id].did })
  assert.ok(result.success, 'Failed to set visibility where ' + id + ' can see 2.')

  post = bent(ENDORSER_SERVER, 'POST', 'json', { 'Uport-Push-Token': jwts[id] })
  result = await post('/api/report/canSeeMe', { did: CREDS[2].did })
  assert.ok(result.success, 'Failed to set visibility where 2 can see ' + id + '.')
}

Promise.all(pushTokenProms)
  .then(async (jwts) => {
    //console.log("Created push tokens", jwts)

    assert.ok(! await auth({vp}, config), 'VP matched even though the user should not be seen by 0x2.')

    // set visibility such that everyone can see the Secretary
    await Promise.all([
      twoWaySees2(jwts, 6),
      twoWaySees2(jwts, 3),

      /** The concept is that everyone can see 0x2, but these aren't necessary for this test.
      twoWaySees2(jwts, 4),
      twoWaySees2(jwts, 5),
      twoWaySees2(jwts, 7),
      twoWaySees2(jwts, 8),
      twoWaySees2(jwts, 9)
      **/
    ])

    assert.ok(await auth({vp}, config), 'Good VP failed to match.')

    const prevHolder = vp.holder
    vp.holder = CREDS[4].did
    assert.ok(! await auth({vp}, config), 'An incorrect holder matched.')
    vp.holder = prevHolder

    const prevVpJwt = vp.proof.jwt
    vp.proof.jwt = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0owZVhBaU9pSktWMVFpZlEuZXlKMll5STZleUpqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQVkyOXVkR1Y0ZENJNkltaDBkSEJ6T2k4dmMyTm9aVzFoTG05eVp5SXNJa0IwZVhCbElqb2lUM0puWVc1cGVtRjBhVzl1SWl3aWJXVnRZbVZ5SWpwN0lrQjBlWEJsSWpvaVQzSm5ZVzVwZW1GMGFXOXVVbTlzWlNJc0ltMWxiV0psY2lJNmV5SkFkSGx3WlNJNklsQmxjbk52YmlJc0ltbGtaVzUwYVdacFpYSWlPaUprYVdRNlpYUm9jam93ZURNek16UkdSVFZoTmprMk1UVXhaR00wUkRCRU1ETkdaak5HWWtGaE1rSTJNRFUyT0VVd05tRWlmU3dpY205c1pVNWhiV1VpT2lKUWNtVnphV1JsYm5RaUxDSnpkR0Z5ZEVSaGRHVWlPaUl5TURFNUxUQTBMVEF4SW4wc0ltNWhiV1VpT2lKRGIzUjBiMjUzYjI5a0lFTnllWEIwYjJkeVlYQm9lU0JEYkhWaUluMHNJa0JqYjI1MFpYaDBJanBiSW1oMGRIQnpPaTh2ZDNkM0xuY3pMbTl5Wnk4eU1ERTRMMk55WldSbGJuUnBZV3h6TDNZeElsMHNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpWFgwc0ltcDBhU0k2SW1oMGRIQTZMeTh4TWpjdU1DNHdMakU2TXpBd01DOWhjR2t2WTJ4aGFXMHZNREZITWxZelFrRTNVRk5aUzBJeE1sQXhRa05SUlVwVFF6QWlMQ0p1WW1ZaU9qRTJOVE01TkRJM05ETXNJbWx6Y3lJNkltUnBaRHBsZEdoeU9qQjRNek16TkVaRk5XRTJPVFl4TlRGa1l6UkVNRVF3TTBabU0wWmlRV0V5UWpZd05UWTRSVEEyWVNKOS5OLUtPd0RaeUVkYWtiWnlYRlBHUUQ1UTFSakRmcnF1a3NaM1kxY2pJTk5vNFRwQVFmT2luSVFqZHBZbFBWRjBCcWQxNGp5ZHZDQWJ5dEhvT3cyQkNKdyJdfSwibmJmIjoxNjUzOTQyNzQzLCJpc3MiOiJkaWQ6ZXRocjoweDMzMzRGRTVhNjk2MTUxZGM0RDBEMDNGZjNGYkFhMkI2MDU2OEUwNmEifQ.5x8voAZL3TuhSjb-zoDClua3fFXRPsB1Q-ypT-xWV9MjMkk2M5mmkU2sUJkFl8LIoK-7RuS0SkA2ZiW1ZdlHjg' // changed second-to-last character from i to j
    assert.ok(! await auth({vp}, config), 'An incorrect VP signature matched.')
    vp.proof.jwt = prevVpJwt

    const prevVcJwt = vp.verifiableCredential[0].proof.jwt
    vp.verifiableCredential[0].proof.jwt = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJAY29udGV4dCI6Imh0dHBzOi8vc2NoZW1hLm9yZyIsIkB0eXBlIjoiT3JnYW5pemF0aW9uIiwibWVtYmVyIjp7IkB0eXBlIjoiT3JnYW5pemF0aW9uUm9sZSIsIm1lbWJlciI6eyJAdHlwZSI6IlBlcnNvbiIsImlkZW50aWZpZXIiOiJkaWQ6ZXRocjoweDMzMzRGRTVhNjk2MTUxZGM0RDBEMDNGZjNGYkFhMkI2MDU2OEUwNmEifSwicm9sZU5hbWUiOiJQcmVzaWRlbnQiLCJzdGFydERhdGUiOiIyMDE5LTA0LTAxIn0sIm5hbWUiOiJDb3R0b253b29kIENyeXB0b2dyYXBoeSBDbHViIn0sIkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXX0sImp0aSI6Imh0dHA6Ly8xMjcuMC4wLjE6MzAwMC9hcGkvY2xhaW0vMDFHMlYzQkE3UFNZS0IxMlAxQkNRRUpTQzAiLCJuYmYiOjE2NTM5NDI3NDMsImlzcyI6ImRpZDpldGhyOjB4MzMzNEZFNWE2OTYxNTFkYzREMEQwM0ZmM0ZiQWEyQjYwNTY4RTA2YSJ9.N-KOwDZyEdakbZyXFPGQD5Q1RjDfrquksZ3Y1cjINNo4TpAQfOinIQjdpYlPVF0Bqd14jydvCAbytHoOw2BCKw' // changed second-to-last character from J to K
    assert.ok(! await auth({vp}, config), 'An incorrect VC signature matched.')
    vp.verifiableCredential[0].proof.jwt = prevVcJwt

  })

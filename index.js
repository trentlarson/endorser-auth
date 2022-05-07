
/**

   to install/build: yarn add @veramo/did-jwt bent

   to test: uncomment the last line and run: node index.js

   to package: zip -rq function.zip index.js node_modules

 **/

const checkJwt = async (jwt, didJwtLib) => {

  const {payload, header, signature, data} = didJwtLib.decodeJWT(jwt)
  if (!payload || !header) {
    console.log('Unverified JWT')
    return false
  } else if (payload.exp < Math.floor(new Date().getTime() / 1000) ) {
    console.log('JWT has expired.')
    return false
  } else if (header.typ === 'none') {
    console.log('Insecure JWT type')
    return false
  }
  return true
}

exports.handler = async (input) => {

  console.log('got input', input)

  const did = 'did:ethr:0x000Ee5654b9742f6Fe18ea970e32b97ee2247B51'
  const privateKeyHex = '01a3172cd9e334210b2669dce737d435beefe5c99802ded607c44cd85c96666b'
  const checkingDid = 'did:ethr:0x111c4aCD2B13e26137221AC86c2c23730c9A315A'

  const didJwt = require('did-jwt')
  const signer = didJwt.SimpleSigner(privateKeyHex)
  //console.log('got signer')

  if (!checkJwt(input.jwt, didJwt)) {
    return false
  }

  const nowEpoch = Math.floor(Date.now() / 1000)
  const endEpoch = nowEpoch + 60
  const tokenPayload = { exp: endEpoch, iat: nowEpoch, iss: did }
  const jwt = await didJwt.createJWT(tokenPayload, { issuer: did, signer })
  //console.log('created jwt', jwt)

  const host = 'https://endorser.ch:3000'
  //const host = 'https://test.endorser.ch:8000'
  //const host = 'http://localhost:3000'
  const url = host + '/api/report/issuersWhoClaimedOrConfirmed?claimId=' + input.claimId
  const bent = require('bent')
  const options = {
    "Content-Type": "application/json",
    "Uport-Push-Token": jwt
  }
  const getJson = bent('json', options)
  const response = await getJson(url)
  //console.log('got response', response)

  const result = response.result.indexOf(checkingDid) > -1

  console.log('gave result', result)
  return result;
}

// Locally test with this:
//exports.handler({ claimId: "01G2BKD9VD9JRYS92X7D8D3CZB", jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2NTE5NDQyODQsImV4cCI6MTY1MjAwNDI4NCwiaXNzIjoiZGlkOmV0aHI6MHgwMDBFZTU2NTRiOTc0MmY2RmUxOGVhOTcwZTMyYjk3ZWUyMjQ3QjUxIn0.43EpuZZgzKGySW1Le0d7cyP_n7CvDVk7mlz1MGWAOnDHJYLdFfpNymqpcr3E5MrIX12QRzIZQ5kH95bihqJ1ZA' })

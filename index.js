
/**

   to install: yarn add @veramo/did-jwt bent

   to test: uncomment the last line and run: node index.js

   to package: zip -rq function.zip index.js node_modules

 **/

exports.handler = async (input) => {

  console.log('input', input)

  const didJwt = require('did-jwt')

  const did = 'did:ethr:0x000Ee5654b9742f6Fe18ea970e32b97ee2247B51'
  const privateKeyHex = '01a3172cd9e334210b2669dce737d435beefe5c99802ded607c44cd85c96666b'
  const signer = didJwt.SimpleSigner(privateKeyHex)
  console.log('got signer')

  const nowEpoch = Math.floor(Date.now() / 1000)
  const endEpoch = nowEpoch + 60 *1000
  const tokenPayload = { exp: endEpoch, iat: nowEpoch, iss: did }

  console.log('tokenPayload',tokenPayload)

  const jwt = await didJwt.createJWT(tokenPayload, { issuer: did, signer })
  console.log('created jwt', jwt)

  const url = 'http://localhost:3000/api/report/issuersWhoClaimedOrConfirmed?claimId=' + input.claimId
  //const url = 'https://test.endorser.ch:8000/api/report/issuersWhoClaimedOrConfirmed?claimId=' + input.claimId
  const bent = require('bent')
  const options = {
    "Content-Type": "application/json",
    "Uport-Push-Token": jwt
  }
  const getJson = bent('json', options)
  const response = await getJson(url)
  console.log('got response:', response)

  return response;
}

// Locally test with this:
exports.handler({ claimId: "01G2BKD9VD9JRYS92X7D8D3CZB" })


/**

   to install/build (requires node 14+):
   - `yarn add @veramo/did-jwt bent`

   sample env vars: ownerDid=did:ethr:0x444D276f087158212d9aA4B6c85C28b9F7994AAC ownerPrivateKeyHex=e7aea73ba5b9b45136bc1bf62b7ecedcd74ae4ec87d0378aeea551c1c14b3fc5 confirmerDid=did:ethr:0x666fb9f5AE22cB932493a4FFF1537c2420E0a4D3 orgName='Cottonwood Cryptography Club' orgRoleName='President'

   to test:
   - `yarn add ethr-did-resolver@0.2.0 uport-credentials@1.1.7 @veramo/did-jwt@^3.1.0 --dev`
   - `node test.js`

   to package: zip -rq function.zip index.js node_modules

**/

/**
   @return iss from JWT if it's valid and hasn't expired and is within the last minute; otherwise null
**/
const checkJwt = (jwt, didJwtLib) => {

  const {payload, header, signature, data} = didJwtLib.decodeJWT(jwt)
  const nowSeconds = Math.floor(new Date().getTime() / 1000)
  if (!payload || !header) {
    console.log('Unverified JWT')
    return null
  } else if (payload.exp < nowSeconds) {
    console.log('JWT has expired.')
    return null
  } else if (payload.iat < nowSeconds - 60) {
    console.log('JWT was issued over 60 seconds ago.')
    return null
  } else if (header.typ === 'none') {
    console.log('JWT typ is insecure.')
    return null
  }
  return payload.iss
}

/**
   input contains a single 'vp' property containing a Verifiable Presentation

   config contains:
     confirmerDid
     orgName
     orgRoleName
     ownerDid
     ownerPrivateKeyHex
   ... though they can be set as environment variables.

   result has details about the claim from Endorser.ch if authN & authZ pass; otherwise, false
**/
exports.auth = async (input, config) => {

  const { vp } = input
  console.log('Got input', input)
  //console.log('Got config', config)

  config = config || {}
  const confirmerDid = config.confirmerDid || process.env.confirmerDid // DID of authority (whose confirmation is required)
  const orgName = config.orgName || process.env.orgName
  const orgRoleName = config.orgRoleName || process.env.orgRoleName
  const ownerDid = config.ownerDid || process.env.ownerDid // DID of this agent's user
  const ownerPrivateKeyHex = config.ownerPrivateKeyHex || process.env.ownerPrivateKeyHex // private key of this agent's user

  const didJwt = require('did-jwt')
  const signer = didJwt.SimpleSigner(ownerPrivateKeyHex)
  //console.log('Got signer.')

  const claimId = vp.verifiableCredential[0].id.substring(vp.verifiableCredential[0].id.lastIndexOf('/'))

  const nowEpoch = Math.floor(Date.now() / 1000)
  const endEpoch = nowEpoch + 60
  const tokenPayload = { exp: endEpoch, iat: nowEpoch, iss: ownerDid }
  const accessJwt = await didJwt.createJWT(tokenPayload, { issuer: ownerDid, signer })
  console.log('Created access jwt', accessJwt)

  //const host = 'https://endorser.ch:3000'
  //const host = 'https://test.endorser.ch:8000'
  const host = 'http://localhost:3000'
  const bent = require('bent')
  const options = {
    "Content-Type": "application/json",
    "Uport-Push-Token": accessJwt
  }
  const getJson = bent('json', options)

  // first check that the claim is as expected
  const claimUrl = host + '/api/claim/' + claimId
  const claimResponse = await getJson(claimUrl)
  console.log('Got claim response', JSON.stringify(claimResponse, null, 2))
  const claim = claimResponse.claim
  // (alternative approach is to pull org_role_claim record from the server)
  const start = claim.member.startDate && new Date(claim.member.startDate)
  const ended = claim.member.endDate && new Date(claim.member.endDate)
  if (claim['@type'] != 'Organization'
      || claim.name != orgName
      || claim.member['@type'] != 'OrganizationRole'
      || claim.member.member.identifier != vp.holder
      || claim.member.roleName != orgRoleName
      || (claim.member.startDate && new Date() < start)
      || (claim.member.endDate && ended < new Date())) {
    // this claim isn't a valid organizational claim
    console.log('This claim did not match criteria:')
    console.dir(claim)
    return false
  }

  // now check confirmations of that claim
  const confirmUrl = host + '/api/report/issuersWhoClaimedOrConfirmed?claimId=' + claimId
  const confirm = await getJson(confirmUrl)
  //console.log('Got confirmation', confirm)
  const result = confirm.result.indexOf(confirmerDid) > -1

  console.log('Giving result', result)
  return result;
}

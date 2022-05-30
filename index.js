
/**

   to install/build: yarn add @veramo/did-jwt bent

   sample env vars: OWNER_DID=did:ethr:0x444D276f087158212d9aA4B6c85C28b9F7994AAC OWNER_PRIVATE_KEY_HEX=e7aea73ba5b9b45136bc1bf62b7ecedcd74ae4ec87d0378aeea551c1c14b3fc5 CONFIRMER_DID=did:ethr:0x666fb9f5AE22cB932493a4FFF1537c2420E0a4D3 ORG_NAME='Cottonwood Cryptography Club' ORG_ROLE_NAME='President'

   to test: uncomment the last line (and maybe change host), add sample env vars, and run: node index.js

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

exports.handler = async (input) => {

  console.log('Got input', input)

  const confirmerDid = process.env.CONFIRMER_DID // DID of authority whose confirmation means to proceed
  const orgName = process.env.ORG_NAME
  const orgRoleName = process.env.ORG_ROLE_NAME
  const ownerDid = process.env.OWNER_DID // DID of this agent's user
  const ownerPrivateKeyHex = process.env.OWNER_PRIVATE_KEY_HEX // private key of this agent's user

  const didJwt = require('did-jwt')
  const signer = didJwt.SimpleSigner(ownerPrivateKeyHex)
  //console.log('Got signer.')

  let checkDid = input.did
  if (input.jwt) {
    checkDid = checkJwt(input.jwt, didJwt)
  }
  if (!checkDid) {
    console.log('JWT did not check out.')
    return false
  }

  const nowEpoch = Math.floor(Date.now() / 1000)
  const endEpoch = nowEpoch + 60
  const tokenPayload = { exp: endEpoch, iat: nowEpoch, iss: ownerDid }
  const accessJwt = await didJwt.createJWT(tokenPayload, { issuer: ownerDid, signer })
  //console.log('Created access jwt', accessJwt)

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
  const claimUrl = host + '/api/claim/' + input.claimId
  const claimResponse = await getJson(claimUrl)
  console.log('Got claim response', claimResponse)
  const claim = claimResponse.claim
  // (alternative approach is to pull org_role_claim record from the server)
  const start = claim.member.startDate && new Date(claim.member.startDate)
  const ended = claim.member.endDate && new Date(claim.member.endDate)
  if (claim['@type'] != 'Organization'
      || claim.name != orgName
      || claim.member['@type'] != 'OrganizationRole'
      || claim.member.member.identifier != checkDid
      || claim.member.roleName != orgRoleName
      || (claim.startDate && new Date() < started)
      || (claim.endDate && ended < new Date())) {
    // this claim isn't a valid organizational claim
    console.log('Claim did not match criteria.')
    return false
  }

  // now check confirmations of that claim
  const confirmUrl = host + '/api/report/issuersWhoClaimedOrConfirmed?claimId=' + input.claimId
  const confirm = await getJson(confirmUrl)
  //console.log('Got confirmation', confirm)
  const result = confirm.result.indexOf(confirmerDid) > -1

  console.log('Giving result', result)
  return result;
}

// Locally test with a confirmation, eg. 0x3 claim confirmed by 0x6 seen by 0x4
//exports.handler({ claimId: "01G2V3BA7PSYKB12P1BCQEJSC0", jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2NTE5NTQwNTYsImV4cCI6NDgwNTU1NDA1NiwiaXNzIjoiZGlkOmV0aHI6MHgwMDBFZTU2NTRiOTc0MmY2RmUxOGVhOTcwZTMyYjk3ZWUyMjQ3QjUxIn0.sPSlVD71T1cB9dCv68P-EsLULourDsT8wvjHAGCtuSVLvUUhOZDeYgkoHbhVa3nFce6sVF6vmFNvmSZlc9sgxg' })
//exports.handler({ claimId: "01G2V3BA7PSYKB12P1BCQEJSC0", did: 'did:ethr:0x3334FE5a696151dc4D0D03Ff3FbAa2B60568E06a' })

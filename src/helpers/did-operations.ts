import { keyOps } from './key-operation'

export class didOps {
  static async generateDIDDocument(did: string, type: string): Promise<any> {
    const keyPair = await keyOps.generateKeyPair(type)
    const id = `did:volary:${did}`
    return {
      didDoc: {
        '@context': 'https://w3id.org/did/v1',
        id,
        publicKey: [
          {
            id: `${did}#keys-1`,
            type:
              type === 'bls12381g2'
                ? 'Bls12381G2Key2020'
                : 'Ed25519VerificationKey2018',
            owner: did,
            publicKeyBase64: keyPair.publicKey,
          },
        ],
      },
      privateKeyBase64: keyPair.secretKey,
    }
  }

  static issueVC(
    issuerDid: string,
    claims: any,
    vcType: string,
    issuerName: string,
    subjectDID: string,
    secretKey: any
  ): any {
    const signatures: any[] = []
    Object.entries(claims).forEach((claim) => { 
      const claimKey = claim[0]
      const clainValue = claim[1]
      const objectToSign: any = {}
      objectToSign[claimKey] = clainValue
      const signature = keyOps.sign(JSON.stringify(objectToSign), secretKey)
      signatures.push({
        type: 'Ed25519Signature2018',
        created: new Date().toISOString(),
        creator: issuerDid,
        signatureValueBase64: signature,
        claimId: `${subjectDID}#${claim[0]}`,
      })
    })
    const credentialSubject = claims
    credentialSubject['id'] = subjectDID
    return {
      vc: {
        '@context': 'https://w3id.org/did/v1',
        issuer: {
          id: issuerDid,
          issuerName,
        },
        credentialSubject,
        proof: {
          type: 'Ed25519Signature2018',
          created: new Date().toISOString(),
          creator: issuerDid,
          proofOfPurpose: 'assertionMethod',
          verificationMethod: issuerDid,
          signatures,
        },
        type: ['VerifiableCredential', vcType],
      },
    }
  }
}

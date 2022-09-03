/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { KeyOps } from './key-operation'

export class DidOps {
  static async generateDIDDocument(did: string, type: string): Promise<any> {
    try {
      const keyPair = await KeyOps.generateKeyPair(type)
      const id = `did:volary:${did}`
      return {
        status: 1,
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
    } catch (error) {
      return {
        status: 0,
        error,
      }
    }
  }

  static async issueVC(
    issuerDid: string,
    claims: any,
    vcType: string,
    issuerName: string,
    subjectDID: string,
    keypair: any,
    type: any
  ): Promise<any> {
    try {
      if (type === 'bls12381g2') {
        const messages: string[] = []
        Object.entries(claims).forEach((claim) => {
          const claimKey = claim[0]
          const clainValue = claim[1]
          const objectToSign: any = {}
          objectToSign[claimKey] = clainValue
          messages.push(JSON.stringify(objectToSign))
        })
        const signedClaim = await KeyOps.blssign(messages, keypair)
        const credentialSubject = claims
        credentialSubject['id'] = subjectDID
        return {
          status: 1,
          vc: {
            '@context': 'https://w3id.org/did/v1',
            issuer: {
              id: issuerDid,
              issuerName,
            },
            credentialSubject,
            proof: {
              type: 'BbsBlsSignature2020',
              created: new Date().toISOString(),
              creator: issuerDid,
              proofOfPurpose: 'assertionMethod',
              verificationMethod: issuerDid,
              value: signedClaim,
            },
            type: ['VerifiableCredential', vcType],
          },
        }
      }
      const signedClaim = KeyOps.sign(JSON.stringify(claims), keypair.secretKey)
      const credentialSubject = claims
      credentialSubject['id'] = subjectDID
      return {
        status: 1,
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
            value: signedClaim,
          },
          type: ['VerifiableCredential', vcType],
        },
      }
    } catch (error) {
      console.log(error)
      return {
        status: 0,
        error,
      }
    }
  }
}

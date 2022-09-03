/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
import nacl from 'tweetnacl'
import util from 'tweetnacl-util'
import {
  generateBls12381G2KeyPair,
  blsSign,
  blsVerify,
  blsCreateProof,
  blsVerifyProof,
  BlsKeyPair,
  BbsVerifyResult,
} from '@mattrglobal/bbs-signatures'
export class KeyOps {
  static async generateKeyPair(
    type: string
  ): Promise<{ publicKey: string; secretKey: string }> {
    if (type === 'bls12381g2') {
      const keyPair = await generateBls12381G2KeyPair()
      return {
        publicKey: util.encodeBase64(keyPair.publicKey),
        secretKey: util.encodeBase64(keyPair.secretKey),
      }
    }
    const keyPair = nacl.sign.keyPair()
    return {
      publicKey: util.encodeBase64(keyPair.publicKey),
      secretKey: util.encodeBase64(keyPair.secretKey),
    }
  }

  static sign(message: string, secretKey: string): string {
    const signature = nacl.sign.detached(
      util.decodeUTF8(message),
      util.decodeBase64(secretKey)
    )
    return util.encodeBase64(signature)
  }

  static async blsCreateProof(
    messages: [string],
    publicKey: string,
    signature: string,
    nonce: string,
    revealed: []
  ): Promise<string> {
    const uMessages: Uint8Array[] = []
    messages.forEach((message) => {
      uMessages.push(Uint8Array.from(Buffer.from(message, 'utf-8')))
    })
    const proof = await blsCreateProof({
      signature: util.decodeBase64(signature),
      publicKey: util.decodeBase64(publicKey),
      messages: uMessages,
      nonce: Uint8Array.from(Buffer.from(nonce, 'utf8')),
      revealed,
    })
    return util.encodeBase64(proof)
  }

  static async blsVerifyProof(
    messages: [string],
    publicKey: string,
    nonce: string,
    proof: string
  ): Promise<BbsVerifyResult> {
    const uMessages: Uint8Array[] = []
    messages.forEach((message) => {
      uMessages.push(Uint8Array.from(Buffer.from(message, 'utf-8')))
    })
    const verified = await blsVerifyProof({
      publicKey: util.decodeBase64(publicKey),
      messages: uMessages,
      nonce: Uint8Array.from(Buffer.from(nonce, 'utf8')),
      proof: util.decodeBase64(proof),
    })
    return verified
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static async blssign(messages: string[], keyPair: any): Promise<string> {
    const uMessages: Uint8Array[] = []
    messages.forEach((message) => {
      uMessages.push(Uint8Array.from(Buffer.from(message, 'utf-8')))
    })
    const decodedKeyPair: BlsKeyPair = {
      publicKey: util.decodeBase64(keyPair.publicKey),
      secretKey: util.decodeBase64(keyPair.secretKey),
    }
    const signature = await blsSign({
      keyPair: decodedKeyPair,
      messages: uMessages,
    })
    return util.encodeBase64(signature)
  }

  static async blsverify(
    messages: [string],
    publicKey: string,
    signature: string
  ): Promise<BbsVerifyResult> {
    const uMessages: Uint8Array[] = []
    messages.forEach((message) => {
      uMessages.push(Uint8Array.from(Buffer.from(message, 'utf-8')))
    })
    const isVerified = await blsVerify({
      publicKey: util.decodeBase64(publicKey),
      messages: uMessages,
      signature: util.decodeBase64(signature),
    })
    return isVerified
  }

  static verify(
    message: string,
    signature: string,
    publicKey: string
  ): boolean {
    return nacl.sign.detached.verify(
      util.decodeUTF8(message),
      util.decodeBase64(signature),
      util.decodeBase64(publicKey)
    )
  }
}

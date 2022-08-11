import nacl from 'tweetnacl'
import util from 'tweetnacl-util'

export class keyOps {
  static generateKeyPair(): any {
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

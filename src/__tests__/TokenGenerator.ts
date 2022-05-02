import { JWK, JWS } from "node-jose";

class TokenGenerator {
  privateKey: JWK.Key;

  async init(): Promise<void> {
    const keystore = JWK.createKeyStore();
    this.privateKey = await keystore.generate("RSA", 2048, {
      alg: "RS256",
      use: "sig",
    });
  }

  get jwk(){
    return this.privateKey.toJSON();
  }

  async createSignedJWT(payload: unknown): Promise<JWS.CreateSignResult> {
    const payloadJson = JSON.stringify(payload);
    const result = await JWS.createSign(
      { compact: true, fields: { typ: "jwt" } },
      this.privateKey
    )
      .update(payloadJson)
      .final();
    return result
  }
}

export default TokenGenerator;

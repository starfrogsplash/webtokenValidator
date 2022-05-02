import { Jwt, Algorithm } from "jsonwebtoken";
import { JWK } from "node-jose";

import jsonwebtoken from "jsonwebtoken"
import * as express from "express";
import axios, { AxiosResponse } from 'axios'

declare module "express" {
  interface Request {
    user?: Jwt;
  }
}

export interface Options {
  issuer: string;
  audience: string;
  algorithms: string;
}

const validAlgorithms = [
  "HS256", "HS384", "HS512",
  "RS256", "RS384", "RS512",
  "ES256", "ES384", "ES512",
  "PS256", "PS384", "PS512",
  "none"]

const authorize =
  (options: Options) =>
    async (
      req: express.Request,
      res: express.Response,
      next: express.NextFunction
    ): Promise<void | express.Response> => {

      if (!validAlgorithms.includes(options.algorithms)) throw new Error('invalid Algorithm')

        try {
          let result: AxiosResponse<{ keys: Record<string, unknown>[]; }, any>
          try {
            result = await axios.get<{ keys: Record<string, unknown>[] }>(`${options.issuer}/.well-known/jwks.json`)
          } catch (error) {
            return res.status(503).send(error)
          }

          const publicKey = await JWK.asKey(result.data.keys[0])
          const token = req.headers.authorization.split(' ')[1]

          if (!token) return res.status(400).send('no token supplied')

          req.user = jsonwebtoken.verify(token, publicKey.toPEM(), {
            algorithms: [options.algorithms as Algorithm],
            complete: true
          })

          next()

        } catch (error) {
          return res.status(401).send(error)
        }

    }

export default authorize;

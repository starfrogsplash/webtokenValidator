import { Jwt } from "jsonwebtoken";
import { JWK } from "node-jose";

import jsonwebtoken from "jsonwebtoken"
import * as express from "express";
import axios from 'axios'

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

const authorize =
  (options: Options) =>
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): Promise<void | express.Response> => {
    if(options.algorithms !== 'RS256') throw new Error('invalid Algorithm')

    try {

      let result 
      try {
        result = await axios.get<{keys: Record<string, unknown>[]}>(`${options.issuer}/.well-known/jwks.json`)
      } catch (error) {
        return res.status(503).send(error)
      }
    
      const publicKey = await JWK.asKey(result.data.keys[0])
      const token = req.headers.authorization.split(' ')[1]

      if(!token) return res.status(400).send('no token supplied')
  
      req.user = jsonwebtoken.verify(token, publicKey.toPEM(), {
        algorithms: [options.algorithms],
        complete: true
      })
  
      next()
      
    } catch (error) {
      return res.status(401).send(error)
    }

  }



   

export default authorize;

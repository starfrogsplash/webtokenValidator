import nock from "nock";
import { createRequest, createResponse } from "node-mocks-http";
import authorise from "./index";
import TokenGenerator from "./__tests__/TokenGenerator";

const tokenGenerator = new TokenGenerator();
const options = {
  issuer: "http://issuer.com",
  audience: "audience",
  algorithms: "RS256",
};
const currentTime = Math.round(Date.now() / 1000);
const claims = {
  sub: "foo",
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10,
};

beforeAll(async () => {
  await tokenGenerator.init();
});

beforeEach(async () => {
  nock(options.issuer)
    .persist()
    .get("/.well-known/jwks.json")
    .reply(200, { keys: [tokenGenerator.jwk] });
});


describe("A request with a valid access token", () => {
  test("should add a user object containing the token claims to the request", async () => {
    const res = createResponse();
    const next = jest.fn();
    const token = await tokenGenerator.createSignedJWT(claims);
    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    
    const jwtHeader = {
      "alg": "RS256",
      "kid": expect.any(String),
      "typ": "jwt"
    }
    await authorise(options)(req, res, next);
    expect(req.user).toHaveProperty("payload", claims);
    expect(req.user).toHaveProperty("header", jwtHeader);
    expect(req.user).toHaveProperty("signature", expect.any(String));
  });
});

describe("Issuer responds with a public key which does not correspond with the private key generated", () => {
  test("should return 401", async () => {
    const res = createResponse();
    const next = jest.fn();
    const newTokenGen = new TokenGenerator() 
    await newTokenGen.init()
    const token = await newTokenGen.createSignedJWT(claims);
    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);
    expect(req).not.toHaveProperty("user");
    expect(res.statusCode).toEqual(401)

  });
});

describe("A request with a inValid token", () => {
  test("should return 401", async () => {
    const res = createResponse();
    const next = jest.fn();
    const token = 'askjdhaskdhasd434';
    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);
    expect(req).not.toHaveProperty("user");
    expect(res.statusCode).toEqual(401)

  });
});

describe("no token supplied", () => {
  test("should return 400", async () => {
    const res = createResponse();
    const next = jest.fn();
    const req = createRequest({
      headers: {
        Authorization: `Bearer `,
      },
    });

    await authorise(options)(req, res, next);
    expect(req).not.toHaveProperty("user");
    expect(res.statusCode).toEqual(400)
  });
});

describe("internal server error", () => {
  test("should return 503", async () => {
    nock.restore()

    nock(options.issuer)
    .persist()
    .get("/.well-known/jwks.json")
    .reply(503);

    const res = createResponse();
    const next = jest.fn();
    const newTokenGen = new TokenGenerator() 
    await newTokenGen.init()
    const token = await newTokenGen.createSignedJWT(claims);
    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    

    await authorise(options)(req, res, next);
    expect(req).not.toHaveProperty("user");
    expect(res.statusCode).toEqual(503)

  });
});

// no token

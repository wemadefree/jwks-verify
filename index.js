'use strict'

const JwksClient = require('jwks-rsa');
const jsonwebtoken = require('jsonwebtoken');

const jwksClients = {};

async function jwksVerify(issuer, audience, jwksUri, token, jwksClientOptions, jwtVerifyOptions) {
    if (!issuer || typeof issuer !== 'string') throw new Error('issuer required');
    if (!audience || typeof audience !== 'string') throw new Error('audience required');
    if (!jwksUri || typeof jwksUri !== 'string') throw new Error('jwksUri required');
    if (!token || typeof token !== 'string') throw new Error('token required');

    let { header } = jsonwebtoken.decode(token, { complete: true });

    let jwksClient = jwksClients[jwksUri];
    if (!jwksClient) {
        jwksClient = jwksClients[jwksUri] = JwksClient({
            cache: true,
            cacheMaxAge: 3600e3,
            cacheMaxEntries: 100,
            rateLimit: true,
            jwksRequestsPerMinute: 100,
            strictSsl: true,
            jwksUri: jwksUri,
            ...jwksClientOptions || {},
        });
    }

    if (!header.kid || typeof header.kid !== 'string') {
        throw new Error('header.kid required');
    }

    let key = await jwksClient.getSigningKeyAsync(header.kid);
    let publicKey = key.getPublicKey();

    if (!publicKey || typeof publicKey !== 'string') {
        throw new Error('key.publicKey required');
    }

    return jsonwebtoken.verify(token, publicKey, {
        issuer,
        audience,
        algorithms: ['RS256'],
        ...jwtVerifyOptions || {},
    });
}

async function verifyGoogleJwt(projectId, token) {
    const issuer = `https://securetoken.google.com/${projectId}`;
    const keyServer = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
    return await jwksVerify(issuer, projectId, keyServer, token);
}

Object.defineProperty(exports, "__esModule", { value: true });
exports.jwksVerify = jwksVerify;
exports.verifyGoogleJwt = verifyGoogleJwt;

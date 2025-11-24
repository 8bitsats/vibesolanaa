/**
 * Cloudflare Access JWT Validation
 * Validates JWT tokens from Cloudflare Access to secure the application
 */

import { createLogger } from '../logger';

const logger = createLogger('CloudflareAccess');

interface CloudflareAccessPayload {
    aud: string;
    email: string;
    exp: number;
    iat: number;
    nonce?: string;
    identity_nonce?: string;
    sub: string;
    iss: string;
}

interface JWKSKey {
    kid: string;
    kty: string;
    alg: string;
    use: string;
    e: string;
    n: string;
}

interface JWKS {
    keys: JWKSKey[];
}

/**
 * Cache for JWKS keys to avoid repeated fetches
 */
let jwksCache: JWKS | null = null;
let jwksCacheTime = 0;
const JWKS_CACHE_TTL = 3600000; // 1 hour

/**
 * Fetch JWKS from Cloudflare Access
 */
async function fetchJWKS(teamDomain: string): Promise<JWKS> {
    const now = Date.now();

    // Return cached JWKS if still valid
    if (jwksCache && (now - jwksCacheTime) < JWKS_CACHE_TTL) {
        return jwksCache;
    }

    const jwksUrl = `https://${teamDomain}/cdn-cgi/access/certs`;
    logger.debug('Fetching JWKS from', { jwksUrl });

    const response = await fetch(jwksUrl);
    if (!response.ok) {
        throw new Error(`Failed to fetch JWKS: ${response.statusText}`);
    }

    jwksCache = await response.json() as JWKS;
    jwksCacheTime = now;

    return jwksCache;
}

/**
 * Import a JWK key for verification
 */
async function importJWK(jwk: JWKSKey): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
        'jwk',
        {
            kty: jwk.kty,
            n: jwk.n,
            e: jwk.e,
            alg: jwk.alg,
            ext: true,
        },
        {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-256',
        },
        false,
        ['verify']
    );
}

/**
 * Decode JWT header without verification
 */
function decodeJWTHeader(token: string): { kid?: string; alg?: string } {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }

    const header = JSON.parse(atob(parts[0]));
    return header;
}

/**
 * Decode JWT payload without verification
 */
function decodeJWTPayload(token: string): CloudflareAccessPayload {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }

    const payload = JSON.parse(atob(parts[1]));
    return payload;
}

/**
 * Verify JWT signature
 */
async function verifyJWTSignature(
    token: string,
    publicKey: CryptoKey
): Promise<boolean> {
    const parts = token.split('.');
    if (parts.length !== 3) {
        return false;
    }

    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const signature = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

    return await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        publicKey,
        signature,
        data
    );
}

/**
 * Validate Cloudflare Access JWT
 */
export async function validateCloudflareAccessJWT(
    request: Request,
    env: Env
): Promise<CloudflareAccessPayload | null> {
    try {
        // Extract JWT from Cf-Access-Jwt-Assertion header
        const token = request.headers.get('Cf-Access-Jwt-Assertion');
        if (!token) {
            logger.debug('No Cf-Access-Jwt-Assertion header found');
            return null;
        }

        // Decode header to get kid
        const header = decodeJWTHeader(token);
        if (!header.kid) {
            logger.warn('JWT missing kid in header');
            return null;
        }

        // Decode payload
        const payload = decodeJWTPayload(token);

        // Check expiration
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp < now) {
            logger.warn('JWT expired', { exp: payload.exp, now });
            return null;
        }

        // Validate audience (Policy AUD)
        const expectedAudience = env.CF_ACCESS_ID;
        if (!expectedAudience) {
            logger.warn('CF_ACCESS_ID not configured');
            return null;
        }

        if (payload.aud !== expectedAudience) {
            logger.warn('JWT audience mismatch', {
                expected: expectedAudience,
                received: payload.aud
            });
            return null;
        }

        // Extract team domain from issuer
        const issuerMatch = payload.iss?.match(/https:\/\/([^\/]+)/);
        if (!issuerMatch) {
            logger.warn('Invalid issuer format', { iss: payload.iss });
            return null;
        }
        const teamDomain = issuerMatch[1];

        // Fetch JWKS and find matching key
        const jwks = await fetchJWKS(teamDomain);
        const jwk = jwks.keys.find(k => k.kid === header.kid);
        if (!jwk) {
            logger.warn('No matching key found in JWKS', { kid: header.kid });
            return null;
        }

        // Import key and verify signature
        const publicKey = await importJWK(jwk);
        const isValid = await verifyJWTSignature(token, publicKey);

        if (!isValid) {
            logger.warn('JWT signature verification failed');
            return null;
        }

        logger.debug('JWT validated successfully', {
            email: payload.email,
            sub: payload.sub
        });

        return payload;
    } catch (error) {
        logger.error('JWT validation error', error);
        return null;
    }
}

/**
 * Middleware to enforce Cloudflare Access authentication
 */
export async function cloudflareAccessMiddleware(
    request: Request,
    env: Env
): Promise<CloudflareAccessPayload | Response> {
    // Skip if Cloudflare Access is not configured
    if (!env.CF_ACCESS_ID || !env.CF_ACCESS_SECRET) {
        logger.debug('Cloudflare Access not configured, skipping validation');
        return new Response('Cloudflare Access not configured', { status: 500 });
    }

    const payload = await validateCloudflareAccessJWT(request, env);

    if (!payload) {
        return new Response('Unauthorized - Invalid or missing Cloudflare Access token', {
            status: 401,
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }

    return payload;
}

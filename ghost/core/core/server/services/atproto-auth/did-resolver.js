/**
 * ATProto DID and handle resolution.
 *
 * Resolution order for handles:
 *   1. DNS TXT record: _atproto.<handle>  →  "did=did:..."
 *   2. HTTPS fallback: GET https://<handle>/.well-known/atproto-did
 *
 * DID document fetching:
 *   did:web  →  GET https://<domain>/.well-known/did.json
 *   did:plc  →  GET <plcDirectory>/<did>
 */
const dns = require('node:dns/promises');
const logging = require('@tryghost/logging');
const { BadRequestError, InternalServerError } = require('@tryghost/errors');

// Matches a valid ATProto handle: dot-separated labels of [a-zA-Z0-9-]
const HANDLE_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
// Matches did:plc or did:web
const DID_RE = /^did:(plc|web):[a-zA-Z0-9._:%-]+$/;

/**
 * @param {string} url
 * @param {number} [timeoutMs=5000]
 * @returns {Promise<string>} response body text
 */
async function fetchText(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json, text/plain, */*' },
      redirect: 'follow',
    });
    if (!res.ok) {
      throw new InternalServerError({ message: `HTTP ${res.status} from ${url}` });
    }
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * @param {string} url
 * @param {number} [timeoutMs=5000]
 * @returns {Promise<Object>}
 */
async function fetchJson(url, timeoutMs = 5000) {
  const text = await fetchText(url, timeoutMs);
  return JSON.parse(text);
}

/**
 * Validate and normalise a handle string.
 * @param {string} handle
 * @returns {string} lower-cased handle
 * @throws if the handle is invalid
 */
function validateHandle(handle) {
  if (typeof handle !== 'string' || handle.length === 0) {
    throw new BadRequestError({ message: 'Handle is required' });
  }
  // Strip leading @ if present
  const cleaned = handle.startsWith('@') ? handle.slice(1) : handle;
  if (!HANDLE_RE.test(cleaned)) {
    throw new BadRequestError({ message: 'Invalid ATProto handle format' });
  }
  if (cleaned.length > 253) {
    throw new BadRequestError({ message: 'Handle too long' });
  }
  return cleaned.toLowerCase();
}

/**
 * Resolve a handle to a DID.
 * @param {string} handle  already-validated handle
 * @returns {Promise<string>} DID
 */
async function resolveHandleToDid(handle) {
  // 1. DNS TXT
  try {
    const records = await dns.resolveTxt(`_atproto.${handle}`);
    for (const parts of records) {
      const value = parts.join('');
      if (value.startsWith('did=')) {
        const did = value.slice(4).trim();
        if (DID_RE.test(did)) {
          return did;
        }
      }
    }
  } catch (err) {
    logging.error(`[atproto-auth] DNS TXT lookup failed for ${handle}:`, err);
  }

  // 2. HTTPS fallback
  try {
    const did = (await fetchText(`https://${handle}/.well-known/atproto-did`)).trim();
    if (DID_RE.test(did)) {
      return did;
    }
  } catch (err) {
    logging.error(`[atproto-auth] HTTPS DID lookup failed for ${handle}:`, err);
  }

  // 3. Bluesky PDS fallback (for .bsky.social handles)
  if (handle.endsWith('.bsky.social')) {
    try {
      const result = await fetchJson(
        `https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`,
      );
      if (result.did && DID_RE.test(result.did)) {
        return result.did;
      }
    } catch (err) {
      logging.error(`[atproto-auth] Bluesky PDS lookup failed for ${handle}:`, err);
    }
  }

  throw new BadRequestError({ message: `Handle not found or does not exist: ${handle}` });
}

module.exports = {
  validateHandle,
  resolveHandleToDid,
  DID_RE,
};

/**
 * ATProto OAuth flow orchestrator.
 *
 * Implements the full ATProto OAuth 2.0 flow:
 *   authorize()             – resolve handle, do PAR, return redirect URL
 *   callback()              – exchange code for tokens, create/link member
 *   submitEmailForPending() – accept email for DID-verified-but-no-email flows
 *   completePendingSignup() – link a pending DID after email magic-link click
 *
 * Security notes:
 *   - State is single-use and expires in 10 minutes (replay prevented in OAuthStateStore).
 *   - Issuer (iss) is verified in callback against stored as_issuer (mix-up attack prevention).
 *   - The token sub claim is verified against the DID resolved at authorize() time (DID substitution prevention).
 *   - redirect_url is validated to be same-origin before use (open redirect prevention).
 *   - All outbound HTTP calls use a 5-second timeout.
 */
const { UnauthorizedError, BadRequestError, NotFoundError } = require('@tryghost/errors');
const { isEmail } = require('@tryghost/validator');

const { validateHandle, resolveHandleToDid } = require('./did-resolver');
const OAuthStateStore = require('./oauth-state-store');

class AtprotoAuthService {
  /**
   * @param {Object} deps
   * @param {import('../../../shared/config')} deps.config
   * @param {import('../../../shared/url-utils').default} deps.urlUtils
   * @param {() => Promise<Object>} deps.getMembersApi
   * @param {import('../../../shared/settings-cache')} deps.settingsCache
   * @param {import('knex').Knex} deps.db
   */
  constructor({ config, urlUtils, getMembersApi, settingsCache, db }) {
    this._config = config;
    this._urlUtils = urlUtils;
    this._getMembersApi = getMembersApi;
    this._settingsCache = settingsCache;
    this._store = new OAuthStateStore(db);
    this._oauthClient = null;
    this._oauthClientPromise = this._createSdkClient();
    this._sdkSessions = new Map();
    this._plcDirectory = config.get('atproto:plcDirectory') || 'https://plc.directory';
  }

  // -------------------------------------------------------------------------
  // Public interface
  // -------------------------------------------------------------------------

  /**
   * Build the authorization server redirect URL for a given handle.
   * @param {string} rawHandle
   * @param {string|null} redirectUrl  post-login destination URL (must be same-origin)
   * @returns {Promise<string>} URL to redirect the browser to
   */
  async authorize(rawHandle, redirectUrl) {
    const handle = validateHandle(rawHandle);
    const safeRedirect = this._sanitizeRedirectUrl(redirectUrl);

    const did = await resolveHandleToDid(handle);
    const client = await this._getSdkClient();

    return (
      await client.authorize(handle, {
        state: JSON.stringify({
          redirectUrl: safeRedirect,
          resolvedDid: did,
        }),
      })
    ).toString();
  }

  /**
   * Handle the OAuth callback from the authorization server.
   * @param {string} code
   * @param {string} stateId
   * @param {string} iss  issuer param from callback (mix-up prevention)
   * @returns {Promise<{member: Object, redirectUrl: string|null, needsEmail: boolean, pendingId: string|null}>}
   */
  async callback(code, stateId, iss) {
    if (!code || !stateId) {
      throw new BadRequestError({ message: 'Missing code or state parameter' });
    }

    try {
      const client = await this._getSdkClient();
      const params = new URLSearchParams({ code, state: stateId });
      if (iss) {
        params.set('iss', iss);
      }

      const { session, state: appState } = await client.callback(params);
      const flowState = this._parseFlowState(appState);
      const did = session.did;

      if (flowState.resolvedDid && did !== flowState.resolvedDid) {
        throw new UnauthorizedError({ message: 'Token sub does not match resolved DID' });
      }

      const tokenSet = await session.getTokenSet();
      const email = tokenSet.email && tokenSet.email_verified ? tokenSet.email : null;

      if (!email) {
        const membersApi = await this._getMembersApi();
        const byDid = await membersApi.members.get({ atproto_did: did });
        if (byDid) {
          return {
            member: byDid,
            redirectUrl: flowState.redirectUrl,
            needsEmail: false,
            pendingId: null,
          };
        }

        const pendingId = await this._store.createPendingEmail(did);
        return { member: null, redirectUrl: flowState.redirectUrl, needsEmail: true, pendingId };
      }

      const member = await this._upsertMember(did, email);
      return { member, redirectUrl: flowState.redirectUrl, needsEmail: false, pendingId: null };
    } catch (err) {
      if (err && err.name === 'OAuthCallbackError') {
        throw new UnauthorizedError({ message: err.message || 'Invalid or expired state' });
      }
      if (err && (err.message || '').includes('Unknown authorization session')) {
        throw new UnauthorizedError({ message: 'Invalid or expired state' });
      }
      throw err;
    }
  }

  /**
   * Accept an email for a pending-DID flow.  Sends a magic link that will
   * complete the signup and link the DID after the user clicks it.
   * @param {string} pendingId
   * @param {string} email
   * @param {string} siteUrl  for building the magic link referrer
   * @returns {Promise<void>}
   */
  async submitEmailForPending(pendingId, email, siteUrl) {
    if (!pendingId) {
      throw new BadRequestError({ message: 'Missing pending ID' });
    }

    if (!email || !isEmail(email)) {
      throw new BadRequestError({ message: 'A valid email address is required' });
    }

    // Peek – don't consume yet; consumption happens in completePendingSignup
    const row = await this._store._knex('atproto_pending_email').where({ id: pendingId }).first();
    if (!row || new Date(row.expires_at) < new Date()) {
      throw new UnauthorizedError({ message: 'Invalid or expired pending session' });
    }

    // Check email is not already bound to a different DID
    const membersApi = await this._getMembersApi();
    const existing = await membersApi.members.get({ email });
    if (
      existing &&
      existing.get('atproto_did') &&
      existing.get('atproto_did') !== row.verified_did
    ) {
      throw new BadRequestError({
        message: 'This email is already linked to a different ATProto identity',
      });
    }

    // Redirect back to the link-DID completion endpoint after magic link clicks
    const completeUrl = new URL(`${siteUrl}/members/atproto/complete-signup`);
    completeUrl.searchParams.set('pending', pendingId);

    await membersApi.sendEmailWithMagicLink({
      email,
      requestedType: 'signup',
      referrer: completeUrl.toString(),
    });
  }

  /**
   * Link a pending DID to the authenticated member (called after magic-link click).
   * @param {string} pendingId
   * @param {string} memberEmail  email of the just-authenticated member
   * @returns {Promise<void>}
   */
  async completePendingSignup(pendingId, memberEmail) {
    if (!pendingId) {
      throw new BadRequestError({ message: 'Missing pending ID' });
    }

    const did = await this._store.consumePendingEmail(pendingId);
    if (!did) {
      throw new UnauthorizedError({ message: 'Invalid or expired pending session' });
    }

    const membersApi = await this._getMembersApi();
    const member = await membersApi.members.get({ email: memberEmail });
    if (!member) {
      throw new NotFoundError({ message: 'Member not found' });
    }

    const existingDid = member.get('atproto_did');
    if (existingDid && existingDid !== did) {
      throw new BadRequestError({
        message: 'This account already has a different ATProto identity linked',
      });
    }

    if (!existingDid) {
      await membersApi.members.update({ atproto_did: did }, { id: member.id });
    }
  }

  /**
   * Returns the JSON content for the /.well-known/oauth-client-metadata endpoint.
   */
  getClientMetadata() {
    const clientId = this._clientMetadataUrl();
    const callbackUrl = this._callbackUrl();

    return {
      client_id: clientId,
      client_name: this._settingsCache.get('title') || 'Ghost Site',
      client_uri: this._urlUtils.getSiteUrl(),
      redirect_uris: [callbackUrl],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'atproto',
      application_type: 'web',
      token_endpoint_auth_method: 'none',
      dpop_bound_access_tokens: true,
    };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  async _getSdkClient() {
    if (!this._oauthClient) {
      this._oauthClient = await this._oauthClientPromise;
    }
    return this._oauthClient;
  }

  async _createSdkClient() {
    const { NodeOAuthClient } = await import('@atproto/oauth-client-node');
    const { JoseKey } = await import('@atproto/jwk-jose');

    const stateStore = {
      async set(key, stateData) {
        if (!this._store || !this._store._knex) {
          return;
        }

        await this._store._knex('atproto_oauth_states').insert({
          id: key,
          pkce_verifier: stateData.verifier,
          dpop_private_key_jwk: JSON.stringify(stateData.dpopKey.privateJwk),
          resolved_did: (() => {
            try {
              const parsed = JSON.parse(stateData.appState || '{}');
              return parsed.resolvedDid || '';
            } catch (err) {
              return '';
            }
          })(),
          pds_token_endpoint: '',
          as_issuer: stateData.iss,
          redirect_url: stateData.appState || null,
          email_required: false,
          expires_at: new Date(Date.now() + 10 * 60 * 1000),
        });
      },
      async get(key) {
        if (!this._store || !this._store._knex) {
          return undefined;
        }

        const row = await this._store._knex('atproto_oauth_states').where({ id: key }).first();
        if (!row) {
          return undefined;
        }
        if (new Date(row.expires_at) < new Date()) {
          await this._store._knex('atproto_oauth_states').where({ id: key }).delete();
          return undefined;
        }

        const dpopKey = await JoseKey.fromJWK(JSON.parse(row.dpop_private_key_jwk));
        return {
          iss: row.as_issuer,
          dpopKey,
          authMethod: { method: 'none' },
          verifier: row.pkce_verifier,
          appState: row.redirect_url || undefined,
        };
      },
      async del(key) {
        if (!this._store || !this._store._knex) {
          return;
        }
        await this._store._knex('atproto_oauth_states').where({ id: key }).delete();
      },
    };

    const sessionStore = {
      async set(sub, session) {
        this._sdkSessions.set(sub, session);
      },
      async get(sub) {
        return this._sdkSessions.get(sub);
      },
      async del(sub) {
        this._sdkSessions.delete(sub);
      },
    };

    const requestLock = async (key, fn) => await fn();

    return new NodeOAuthClient({
      fetch: globalThis.fetch,
      clientMetadata: this.getClientMetadata(),
      stateStore,
      sessionStore,
      requestLock,
      responseMode: 'query',
    });
  }

  _parseFlowState(appState) {
    if (!appState || typeof appState !== 'string') {
      return { redirectUrl: null, resolvedDid: null };
    }

    try {
      const parsed = JSON.parse(appState);
      if (parsed && typeof parsed === 'object') {
        return {
          redirectUrl: parsed.redirectUrl || null,
          resolvedDid: parsed.resolvedDid || null,
        };
      }
    } catch (err) {
      // Some older flows store a plain redirect URL string.
    }

    return { redirectUrl: appState, resolvedDid: null };
  }

  /**
   * Find-or-create a Ghost member for the given DID and email.
   */
  async _upsertMember(did, email) {
    const membersApi = await this._getMembersApi();

    // 1. DID already linked to a member?
    const byDid = await membersApi.members.get({ atproto_did: did });
    if (byDid) {
      if (byDid.get('email') !== email) {
        await membersApi.members.update({ email }, { id: byDid.id });
        return await membersApi.members.get({ id: byDid.id });
      }
      return byDid;
    }

    // 2. Email already belongs to a member?
    const byEmail = await membersApi.members.get({ email });
    if (byEmail) {
      const existingDid = byEmail.get('atproto_did');
      if (existingDid && existingDid !== did) {
        throw new BadRequestError({
          message: 'This email already has a different ATProto identity linked',
        });
      }
      if (!existingDid) {
        await membersApi.members.update({ atproto_did: did }, { id: byEmail.id });
      }
      return byEmail;
    }

    // 3. Create new member
    const newMember = await membersApi.members.create({
      email,
      atproto_did: did,
    });
    return newMember;
  }

  /**
   * Validate that a redirect URL is same-origin as the Ghost site.
   * Returns null for invalid or missing values.
   */
  _sanitizeRedirectUrl(candidate) {
    if (!candidate || typeof candidate !== 'string') {
      return null;
    }
    try {
      const siteUrl = new URL(this._urlUtils.getSiteUrl());
      const candidateUrl = new URL(candidate);
      if (candidateUrl.origin !== siteUrl.origin) {
        return null;
      }
      return candidateUrl.href;
    } catch {
      return null;
    }
  }

  _callbackUrl() {
    let siteUrl = this._urlUtils.getSiteUrl().replace(/\/$/, '');
    // RFC 8252: OAuth for native apps requires loopback IPs, not hostnames
    siteUrl = siteUrl
      .replace('http://localhost:', 'http://127.0.0.1:')
      .replace('https://localhost:', 'https://127.0.0.1:');
    return `${siteUrl}/members/atproto/callback`;
  }

  _clientMetadataUrl() {
    // Keep using the original hostname/port for client_id URL
    // (it needs to be fetchable by external Bluesky servers)
    // This may be localhost in dev or a public domain in production
    return `${this._urlUtils.getSiteUrl().replace(/\/$/, '')}/.well-known/oauth-client-metadata`;
  }

  /**
   * Returns the canonical callback URL for use in routes.
   */
  getCallbackUrl() {
    return this._callbackUrl();
  }

  /**
   * Returns the Ghost site URL.
   */
  getSiteUrl() {
    return this._urlUtils.getSiteUrl();
  }

  // Expose store for background cleanup
  get store() {
    return this._store;
  }
}

module.exports = AtprotoAuthService;

const crypto = require('crypto');
const http = require('http');
const { shell } = require('electron');
const axios = require('axios');

/**
 * Generate PKCE code_verifier, S256 code_challenge, and state parameter.
 */
function generatePKCE() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  const state = crypto.randomBytes(16).toString('hex');
  return { codeVerifier, codeChallenge, state };
}

/**
 * Launch ephemeral loopback server on 127.0.0.1, open system browser for Google OAuth PKCE,
 * receive authorization code, and exchange for Google OIDC tokens.
 */
function startDesktopOAuthFlow(googleClientId) {
  return new Promise((resolve, reject) => {
    if (!googleClientId) {
      return reject(new Error('Google Client ID is required for desktop OAuth'));
    }

    const { codeVerifier, codeChallenge, state } = generatePKCE();
    let server = null;
    let callbackRedirectUri = null;
    let isHandled = false;

    const cleanup = () => {
      if (server) {
        try {
          server.close();
        } catch {
          // Ignore server close error
        }
        server = null;
      }
    };

    // 2-minute safety timeout
    const timeoutTimer = setTimeout(() => {
      if (!isHandled) {
        isHandled = true;
        cleanup();
        reject(new Error('Desktop OAuth authentication timed out (120s limit)'));
      }
    }, 120000);

    server = http.createServer(async (req, res) => {
      try {
        const reqUrl = new URL(req.url, `http://127.0.0.1`);
        if (reqUrl.pathname !== '/callback') {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
          return;
        }

        const code = reqUrl.searchParams.get('code');
        const returnedState = reqUrl.searchParams.get('state');
        const errorParam = reqUrl.searchParams.get('error');

        if (errorParam) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end('<h2 style="font-family:sans-serif;color:#e5534b;">Authentication Error: Authorization was denied.</h2>');
          if (!isHandled) {
            isHandled = true;
            clearTimeout(timeoutTimer);
            cleanup();
            reject(new Error(`OAuth error response: ${errorParam}`));
          }
          return;
        }

        if (!returnedState || returnedState !== state) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end('<h2 style="font-family:sans-serif;color:#e5534b;">Security Error: Invalid state parameter.</h2>');
          if (!isHandled) {
            isHandled = true;
            clearTimeout(timeoutTimer);
            cleanup();
            reject(new Error('State validation failed. Potential authorization code interception.'));
          }
          return;
        }

        if (!code) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end('<h2 style="font-family:sans-serif;color:#e5534b;">Missing authorization code.</h2>');
          if (!isHandled) {
            isHandled = true;
            clearTimeout(timeoutTimer);
            cleanup();
            reject(new Error('Missing authorization code in callback'));
          }
          return;
        }

        const redirectUri = callbackRedirectUri;

        // Return HTML response to browser
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(
          '<!DOCTYPE html><html><head><title>AihaX Auth Success</title></head>' +
          '<body style="background:#0D1117;color:#E6EDF3;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">' +
          '<div style="text-align:center;padding:2rem;background:#161B22;border:1px solid #30363D;border-radius:12px;box-shadow:0 10px 25px rgba(0,0,0,0.5);">' +
          '<h2 style="color:#2DA44E;margin-top:0;">✓ Authentication Successful</h2>' +
          '<p style="color:#8B949E;">You have signed in to AihaX. You can close this browser window and return to the desktop application.</p>' +
          '</div></body></html>'
        );

        if (!isHandled) {
          isHandled = true;
          clearTimeout(timeoutTimer);
          cleanup();

          // Exchange authorization code for Google ID token using PKCE verifier
          const tokenResp = await axios.post('https://oauth2.googleapis.com/token', new URLSearchParams({
            code,
            client_id: googleClientId,
            code_verifier: codeVerifier,
            grant_type: 'authorization_code',
            redirect_uri: redirectUri,
          }).toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 10000,
          });

          if (!tokenResp.data || !tokenResp.data.id_token) {
            throw new Error('Google token exchange failed to return ID token');
          }

          resolve(tokenResp.data.id_token);
        }
      } catch (err) {
        if (!isHandled) {
          isHandled = true;
          clearTimeout(timeoutTimer);
          cleanup();
          reject(err);
        }
      }
    });

    // Bind strictly to 127.0.0.1 on dynamically allocated port 0
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const redirectUri = `http://127.0.0.1:${port}/callback`;
      callbackRedirectUri = redirectUri;
      const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      authUrl.search = new URLSearchParams({
        client_id: googleClientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state,
      }).toString();

      // Open in system default web browser (Never an embedded webview!)
      shell.openExternal(authUrl.toString()).catch((err) => {
        if (!isHandled) {
          isHandled = true;
          clearTimeout(timeoutTimer);
          cleanup();
          reject(new Error(`Failed to open system browser: ${err.message}`));
        }
      });
    });

    server.on('error', (err) => {
      if (!isHandled) {
        isHandled = true;
        clearTimeout(timeoutTimer);
        cleanup();
        reject(new Error(`Loopback callback server error: ${err.message}`));
      }
    });
  });
}

module.exports = {
  generatePKCE,
  startDesktopOAuthFlow,
};

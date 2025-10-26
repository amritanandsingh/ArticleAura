// ====== CONFIGURE THESE ======
const COGNITO_DOMAIN = "ap-south-1wneguekrl.auth.ap-south-1.amazoncognito.com"; // no https://
const CLIENT_ID = "2p2ra1i7lpfqrbrkemmm2u4tr5";
const REDIRECT_URI = "https://d1trjzf1dsfjpa.cloudfront.net/"; // must match app client callback
const LOGOUT_URI = "https://d1trjzf1dsfjpa.cloudfront.net/"; // must match app client sign-out
const SCOPES = ["openid", "profile", "email"]; // adjust as needed
// =============================

const authorizeEndpoint = `https://${COGNITO_DOMAIN}/oauth2/authorize`;
const tokenEndpoint = `https://${COGNITO_DOMAIN}/oauth2/token`;
const userInfoEndpoint = `https://${COGNITO_DOMAIN}/oauth2/userInfo`;
const logoutEndpoint = `https://${COGNITO_DOMAIN}/logout`;

// Simple helpers
const qs = (sel) => document.querySelector(sel);
const statusEl = qs("#status");
const profileEl = qs("#profile");
const loginBtn = qs("#loginBtn");
const logoutBtn = qs("#logoutBtn");
const pUsername = qs("#p-username");
const pName = qs("#p-name");
const pEmail = qs("#p-email");
const tokensPre = qs("#tokensPre");

// Base64 URL encoding helpers for PKCE
const toBase64Url = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let str = "";
  for (let i = 0; i < bytes.byteLength; i++)
    str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

async function sha256Base64Url(input) {
  const enc = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return toBase64Url(digest);
}

function randomString(len = 64) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  let out = "";
  const randomVals = new Uint8Array(len);
  crypto.getRandomValues(randomVals);
  for (const v of randomVals) out += chars[v % chars.length];
  return out;
}

// Build the authorize URL for PKCE (Authorization Code with S256)
async function startLogin() {
  const codeVerifier = randomString(64);
  const codeChallenge = await sha256Base64Url(codeVerifier);
  sessionStorage.setItem("pkce_code_verifier", codeVerifier);

  const state = randomString(16);
  sessionStorage.setItem("oauth_state", state);

  const url = new URL(authorizeEndpoint);
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", SCOPES.join(" "));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("state", state);

  window.location.assign(url.toString());
}

// Exchange `code` for tokens
async function exchangeCodeForTokens(code) {
  const codeVerifier = sessionStorage.getItem("pkce_code_verifier");
  if (!codeVerifier)
    throw new Error("Missing PKCE code_verifier in sessionStorage");

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  const resp = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Token exchange failed: ${resp.status} ${text}`);
  }

  const tokens = await resp.json();
  sessionStorage.setItem("oauth_tokens", JSON.stringify(tokens));
  // Clean the query string to look nice
  window.history.replaceState({}, document.title, REDIRECT_URI);
  return tokens;
}

async function fetchUserInfo(accessToken) {
  const resp = await fetch(userInfoEndpoint, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!resp.ok) throw new Error(`UserInfo failed: ${resp.status}`);
  return resp.json();
}

function parseIdToken(idToken) {
  try {
    const payload = idToken.split(".")[1];
    const json = JSON.parse(
      atob(payload.replace(/-/g, "+").replace(/_/g, "/"))
    );
    return json || {};
  } catch {
    return {};
  }
}

function updateUISignedOut() {
  statusEl.textContent = "Not signed in";
  profileEl.hidden = true;
  logoutBtn.hidden = true;
  loginBtn.hidden = false;
}

function updateUISignedIn(tokens, profile) {
  statusEl.textContent = "Signed in";
  loginBtn.hidden = true;
  logoutBtn.hidden = false;
  profileEl.hidden = false;

  // Prefer userInfo; fall back to id token claims
  const idClaims = tokens.id_token ? parseIdToken(tokens.id_token) : {};
  const username = profile.username || idClaims["cognito:username"] || "—";
  const name = profile.name || idClaims.name || "—";
  const email = profile.email || idClaims.email || "—";

  pUsername.textContent = username;
  pName.textContent = name;
  pEmail.textContent = email;

  tokensPre.textContent = JSON.stringify(tokens, null, 2);
}

function getStoredTokens() {
  try {
    return JSON.parse(sessionStorage.getItem("oauth_tokens") || "null");
  } catch {
    return null;
  }
}

async function tryHandleAuthRedirect() {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code) return null;

  // Optional: validate state
  const storedState = sessionStorage.getItem("oauth_state");
  if (storedState && state !== storedState) {
    throw new Error("State mismatch; possible CSRF.");
  }

  return exchangeCodeForTokens(code);
}

async function init() {
  updateUISignedOut();

  // Wire buttons
  loginBtn.addEventListener("click", () => startLogin());
  logoutBtn.addEventListener("click", () => {
    // Clear session storage
    sessionStorage.removeItem("oauth_tokens");
    sessionStorage.removeItem("pkce_code_verifier");
    sessionStorage.removeItem("oauth_state");
    // Redirect to Cognito logout
    const url = new URL(logoutEndpoint);
    url.searchParams.set("client_id", CLIENT_ID);
    url.searchParams.set("logout_uri", LOGOUT_URI);
    window.location.assign(url.toString());
  });

  try {
    // If returning from Hosted UI with ?code=...
    const newTokens = await tryHandleAuthRedirect();
    const tokens = newTokens || getStoredTokens();

    if (tokens && tokens.access_token) {
      // Try userinfo first; if it fails, still show ID token claims
      try {
        const profile = await fetchUserInfo(tokens.access_token);
        updateUISignedIn(tokens, profile);
      } catch {
        updateUISignedIn(tokens, {});
      }
    } else {
      updateUISignedOut();
    }
  } catch (e) {
    statusEl.textContent = `Auth error: ${e.message}`;
    updateUISignedOut();
  }
}

init();

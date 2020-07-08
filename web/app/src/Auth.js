import crypto from 'crypto';

// This performs a raw encoding
function base64URLEncode(str) {
  return str
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

class Auth {
  constructor() {
    this.authenticated = false;
  }

  login(auth_url, client_id, scope, audience, login_uri) {
    // generate a random code
    const verifier = crypto.randomBytes(32);
    const nonce = base64URLEncode(crypto.randomBytes(16));

    // TODO: store this someplace better like the session (we will need it later)
    localStorage.setItem('verifier', base64URLEncode(verifier));
    localStorage.setItem('nonce', nonce);

    const challenge = base64URLEncode(sha256(verifier));
    localStorage.setItem('challenge', challenge);

    console.log('verifier=' + base64URLEncode(verifier));
    console.log('challenge=' + challenge);

    console.log(auth_url);

    // redirect to the oauth service (which will redirect back here)
    window.location.href = `${auth_url}?client_id=${client_id}&audience=${audience}&login_uri=${login_uri}&scope=${scope}&redirect_uri=%2F&response_type=code&code_challenge=${challenge}&nonce=${nonce}`;
  }

  verifier() {
    return localStorage.getItem('verifier');
  }

  logout(cb) {
    this.authenticated = false;
    cb();
  }

  isAuthenticated() {
    return this.authenticated;
  }
}

export default new Auth();

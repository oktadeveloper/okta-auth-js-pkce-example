import OktaAuth from '@okta/okta-auth-js';
import router from '../router';

const ISSUER = process.env.VUE_APP_OKTA_CLIENT_ORGURL + '/oauth2/default';
const CLIENT_ID = process.env.VUE_APP_OKTA_OAUTH2_CLIENT_ID_SPA;
const REDIRECT_URL = window.location.origin + '/authorization-code/callback';

const AUTH_CODE_GRANT_TYPE = 'authorization_code';
const IMPLICIT_GRANT_TYPE = 'implicit';

const responseTypes = {};
responseTypes[AUTH_CODE_GRANT_TYPE] = 'code';
responseTypes[IMPLICIT_GRANT_TYPE] =  ['id_token', 'token'];

const oktaAuth = new OktaAuth({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URL
});

export function validateAccess(to, from, next) {
    getIdToken()
    .then(function(token) {
        if (token) {
            next();
        } else {
            oktaAuth.tokenManager.clear();
            // implicit or pkce?
            var grantParam = to.path.substring(to.path.lastIndexOf('/') + 1);
            var grantType = (responseTypes[grantParam]) ? grantParam : AUTH_CODE_GRANT_TYPE
            loginOkta(grantType);
        }          
    })
    .catch(console.error);
}

export function loginOkta(grantType) {
    oktaAuth.options.grantType = grantType;
    oktaAuth.token.getWithRedirect({
        pkce: true,
        responseType: responseTypes[grantType],
        scopes: ['openid', 'profile', 'email']
    });
}

export function logout() {
    getIdToken()
    .then(function (token) {
        if (token) {
            var idToken = token.idToken;
            oktaAuth.tokenManager.clear();
            window.location.href = ISSUER + '/v1/logout?client_id=' + CLIENT_ID + 
                '&id_token_hint=' + idToken + '&post_logout_redirect_uri=' + window.location.origin 
        } else {
            router.push('/');
        }
    })
}

export function callback() {
    // detect code
    var grantType = (window.location.href.indexOf('code=') > 0) ? 
        AUTH_CODE_GRANT_TYPE : IMPLICIT_GRANT_TYPE;
    oktaAuth.token.parseFromUrl()
    .then((tokens) => {
        tokens.forEach((token) => {
            if (token.idToken) {
                oktaAuth.tokenManager.add('id_token', token);
            } else if (token.accessToken) {
                oktaAuth.tokenManager.add('access_token', token);
            }
        });
        router.push('/profile/' + grantType);
    })
    .catch(console.error);
}

export function getIdToken() {
    return oktaAuth.tokenManager.get('id_token');
}
  
export function getAccessToken() {
    return oktaAuth.tokenManager.get('access_token');
}


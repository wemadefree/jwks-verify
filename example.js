const { jwksVerify } = require('./index')

async function example() {
    const audience = 'my-project-id';
    const issuer = `https://securetoken.google.com/${audience}`;
    const keyServer = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
    const token = '...some JWT issued by Google';
    await jwksVerify(issuer, audience, keyServer, token)
}

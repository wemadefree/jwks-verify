# @olibm/jwks-verify

## Example

```
import { jwksVerify } from '@olibm/jwks-verify'

async function example() {
    const audience = 'my-project-id';
    const issuer = `https://securetoken.google.com/${audience}`;
    const keyServer = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
    const token = '...some JWT issued by Google';
    const verifiedClaims = await jwksVerify(issuer, audience, keyServer, token)
}
```

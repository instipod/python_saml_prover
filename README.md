# python_saml_prover
Simple python web service to prove a user's identity using SAML

## API Details
**GET /retrieve?secret=secret**

Retrieve a new validation token to give a user.
> {"token": "mf2gme9ivrbe9sd95dhqrb92dsj6bzsf"}


**GET /get?secret=secret**

Retrieve the status of the given token.

If a token is proved, calling this URL will remove the token from memory after the current request is finished.
> {'proved':true, 'user':'username'}

**GET /prove?token=token**

This is the URL to send to users to prove their identity.  This URL starts the SAML redirect.

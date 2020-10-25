# python_saml_prover
Simple python web service to prove a user's identity using SAML

## API Details
**GET /retrieve?secret=secret**

Retrieve a new validation token to give a user.


**GET /get?secret=secret**

Retrieve the status of the given token.  Returns JSON:
> {'proved':true, 'user':'username'}

If a token is proved, calling this URL will remove the token from memory after the current request is finished.


**GET /prove?token=token**

This is the URL to send to users to prove their identity.  This URL starts the SAML redirect.

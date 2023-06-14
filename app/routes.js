//
// For guidance on how to create routes see:
// https://prototype-kit.service.gov.uk/docs/create-routes
//

const govukPrototypeKit = require('govuk-prototype-kit')
const router = govukPrototypeKit.requests.setupRouter()

// Add your routes here

const {Issuer, TokenSet} = require('openid-client')
const {createPrivateKey} = require("node:crypto")

const keyString = process.env.private_key

const privateKey = createPrivateKey({
    key: Buffer.from(keyString, "base64"),
    type: "pkcs8",
    format: "der"
})

Issuer.discover("https://oidc.integration.account.gov.uk/.well-known/openid-configuration").then(issuer => {
    const client = new issuer.Client({
            client_id: process.env.client_id,
            redirect_uris: ["http://localhost:8000/oauth/callback"],
            response_type: "code",
            token_endpoint_auth_method: "private_key_jwt",
            token_endpoint_auth_signing_alg: "RS256",
            id_token_signed_response_alg: "ES256",

        },
        {keys: [privateKey.export({format: "jwk"})]}
    )


    let tokenSet

    router.get("/login", (req, res) => {
        console.log(tokenSet)
        if (tokenSet && !tokenSet.expired()) {
            res.redirect("/signin/userinfo")
        } else {
            const loginUrl = client.authorizationUrl({
                scope: "openid email",
                vtr: `["Cl.Cm"]`,
                ui_locales: "en-GB en",
                nonce: 1,
                state: req.session.data["remembered-data"]
            })
            res.redirect(loginUrl)
        }
    })

    router.get("/oauth/callback", async (req, res) => {
        tokenSet = await client.callback(
            "http://localhost:8000/oauth/callback",
            client.callbackParams(req),
            {
                state: req.query.state,
                nonce: "1"
            }
        )
        const userinfo = await client.userinfo(tokenSet.access_token)
        console.log(userinfo)
        req.session.data['userinfo'] = JSON.stringify(userinfo)
        req.session.data['email'] = userinfo.email
        req.session.data['state'] = req.query.state
        res.redirect("/signin/userinfo")
    })
})

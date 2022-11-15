import https from "https"
import { URL } from "url"
import { Strategy as PassportStrategy } from "passport-strategy"
import type { GetUserResponse } from "@notionhq/client/build/src/api-endpoints"

export type NotionPersonUser = Extract<GetUserResponse, { type: "person" }>

export interface NotionOAuthToken {
  access_token: string
  token_type: "bearer"
  bot_id: string
  workspace_id: string
  workspace_name?: string
  workspace_icon?: string
  owner: { type: "workspace" } | { type: "user"; user: NotionPersonUser }
}

export interface NotionStrategyOptions {
  clientID: string
  clientSecret: string
  callbackURL: string
  tokenURL?: string
  authorizationURL?: string
  state?: string
}

export interface NotionVerifyCallback {
  (
    req: unknown, // req,
    accessToken: string, // oauthData.access_token,
    _unknown: undefined, // ? undefined,
    oauthData: NotionOAuthToken, // ? Notion OAuth response?
    userProfileData: GetUserResponse, // ? get /v1/users/me response?
    callback: (err: Error | undefined, user: any, info: unknown) => void
  ): void
}

export default class Strategy extends PassportStrategy {
  name: string
  private _verify: NotionVerifyCallback
  private _options: NotionStrategyOptions
  private _clientSecret: string
  private _clientID: string
  private _tokenURL: string
  private _authorizationURL: string

  constructor(options: NotionStrategyOptions, verify: NotionVerifyCallback) {
    super()

    if (!verify) {
      throw new TypeError("NotionStrategy requires a verify callback")
    }
    if (!options.clientID) {
      throw new TypeError("NotionStrategy requires a clientID")
    }
    if (!options.clientSecret) {
      throw new TypeError("NotionStrategy requires a clientSecret")
    }
    if (!options.callbackURL) {
      throw new TypeError("NotionStrategy require an Callback URL option")
    }

    this.name = "notion"
    this._verify = verify
    this._options = options
    this._clientSecret = options.clientSecret
    this._clientID = options.clientID
    this._tokenURL = options.tokenURL || "https://api.notion.com/v1/oauth/token"
    this._authorizationURL = options.authorizationURL || "https://api.notion.com/v1/oauth/authorize"
  }

  async authenticate(
    req: Parameters<PassportStrategy["authenticate"]>[0],
    options: Parameters<PassportStrategy["authenticate"]>[1]
  ) {
    options = options || {}
    if (req.query && req.query.code) {
      try {
        const oauthData = await this.getOAuthAccessToken(req.query.code as string)
        if (oauthData.owner.type !== "user") {
          throw new Error(`Notion API token not owned by user, instead: ${oauthData.owner.type}`)
        }

        this._verify(
          req,
          oauthData.access_token,
          undefined,
          oauthData,
          oauthData.owner.user,
          (err, user, info) => {
            if (err) return this.error(err)
            if (!user) return this.fail(info as any /* ??? */)
            this.success(user)
          }
        )
      } catch (error) {
        this.error(error as Error)
      }
    } else {
      const authUrl = new URL(this._authorizationURL)
      authUrl.searchParams.set("client_id", this._clientID)
      authUrl.searchParams.set("redirect_uri", this._options.callbackURL)
      authUrl.searchParams.set("response_type", "code")
      if (this._options?.state) {
        authUrl.searchParams.set("state", this._options.state)
      } else if (options.state) {
        authUrl.searchParams.set("state", options.state)
      }
      const location = authUrl.toString()
      this.redirect(location)
    }
  }

  async getOAuthAccessToken(code: string): Promise<NotionOAuthToken> {
    let accessTokenURLObject = new URL(this._tokenURL)

    const accessTokenBody = {
      grant_type: "authorization_code",
      code,
      redirect_uri: this._options.callbackURL,
    }

    const encodedCredential = Buffer.from(`${this._clientID}:${this._clientSecret}`).toString(
      "base64"
    )

    const requestOptions = {
      hostname: accessTokenURLObject.hostname,
      path: accessTokenURLObject.pathname,
      headers: {
        Authorization: `Basic ${encodedCredential}`,
        "Content-Type": "application/json",
      },
      method: "POST",
    }

    return new Promise<NotionOAuthToken>((resolve, reject) => {
      const accessTokenRequest = https.request(requestOptions, (res) => {
        let data = ""
        res.on("data", (d) => {
          data += d
        })

        res.on("end", () => {
          try {
            resolve(JSON.parse(data))
          } catch (error) {
            reject(error)
          }
        })
      })

      accessTokenRequest.on("error", reject)
      accessTokenRequest.write(JSON.stringify(accessTokenBody))
      accessTokenRequest.end()
    })
  }
}

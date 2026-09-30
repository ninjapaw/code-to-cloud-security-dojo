import {
  createHmac,
  randomBytes,
  timingSafeEqual,
  createHash,
} from "node:crypto";

export function equalSecret(left, right) {
  const hash = (value) => createHash("sha256").update(String(value)).digest();
  return timingSafeEqual(hash(left), hash(right));
}

export class Sessions {
  constructor(key, store) {
    this.key = key;
    this.store = store;
  }
  sign(value) {
    return createHmac("sha256", this.key).update(value).digest("base64url");
  }
  async create() {
    const session = {
      id: randomBytes(32).toString("base64url"),
      expires: Date.now() + 3600000,
      csrf: randomBytes(32).toString("base64url"),
      revoked: false,
    };
    await this.store.put(`sessions/${session.id}`, session);
    return { session, token: `${session.id}.${this.sign(session.id)}` };
  }
  async read(cookie = "") {
    const token =
      cookie
        .split(";")
        .map((value) => value.trim())
        .find((value) => value.startsWith("dojo_session="))
        ?.slice(13) || "";
    const [id, signature, extra] = token.split(".");
    if (
      extra ||
      !/^[\w-]{43}$/.test(id || "") ||
      !equalSecret(signature, this.sign(id))
    )
      return null;
    const session = await this.store.get(`sessions/${id}`);
    return session && !session.revoked && session.expires > Date.now()
      ? session
      : null;
  }
  async revoke(session) {
    await this.store.put(`sessions/${session.id}`, {
      ...session,
      revoked: true,
    });
  }
}

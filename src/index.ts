import Cap from "@cap.js/server";

interface ChallengeData {
  challenge: {
    c: number;
    s: number;
    d: number;
  };
  token: string;
  expires: number;
}

interface StoredToken {
  expires: number;
}

const ERR_NOT_FOUND = "NOT_FOUND" as const;
const ERR_EXPIRED = "EXPIRED" as const;

const API_BASE = "/api";
const CHALLENGE_PATH = `${API_BASE}/challenge`;
const REDEEM_PATH = `${API_BASE}/redeem`;
const VALIDATE_PATH = `${API_BASE}/validate`;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
} as const;

// ============ D1 存储函数 ============

async function storeChallenge(env: Env, token: string, challenge: ChallengeData) {
  await env.CAP_DB.prepare(
    "INSERT OR REPLACE INTO challenges (token, challenge_data, expires) VALUES (?, ?, ?)"
  ).bind(token, JSON.stringify(challenge), challenge.expires).run();
}

async function getChallenge(env: Env, token: string): Promise<ChallengeData | null> {
  const result = await env.CAP_DB.prepare(
    "SELECT challenge_data FROM challenges WHERE token = ?"
  ).bind(token).first<{ challenge_data: string }>();
  if (!result) return null;
  return JSON.parse(result.challenge_data);
}

async function deleteChallenge(env: Env, token: string) {
  await env.CAP_DB.prepare("DELETE FROM challenges WHERE token = ?").bind(token).run();
}

async function storeToken(env: Env, tokenHash: string, expires: number) {
  await env.CAP_DB.prepare(
    "INSERT OR REPLACE INTO tokens (token_hash, expires) VALUES (?, ?)"
  ).bind(tokenHash, expires).run();
}

async function getToken(env: Env, tokenHash: string): Promise<StoredToken | null> {
  return await env.CAP_DB.prepare(
    "SELECT expires FROM tokens WHERE token_hash = ?"
  ).bind(tokenHash).first<StoredToken>();
}

async function deleteToken(env: Env, tokenHash: string) {
  await env.CAP_DB.prepare("DELETE FROM tokens WHERE token_hash = ?").bind(tokenHash).run();
}

async function cleanupExpired(env: Env) {
  const now = Date.now();
  await env.CAP_DB.prepare("DELETE FROM challenges WHERE expires < ?").bind(now).run();
  await env.CAP_DB.prepare("DELETE FROM tokens WHERE expires < ?").bind(now).run();
}

// ============ 工具函数 ============

async function hashToken(token: string): Promise<string> {
  const [id, rawToken] = token.split(":");
  if (!id || !rawToken) throw new Error("Invalid token format");
  const encoder = new TextEncoder();
  const data = encoder.encode(rawToken);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hash = Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return `${id}:${hash}`;
}

function createCapInstance() {
  return new Cap({ noFSState: true });
}

function createChallenge() {
  const cap = createCapInstance();
  return cap.createChallenge();
}

async function verifyChallengeSolution(challenge: ChallengeData, solutions: number[]) {
  const cap = createCapInstance();
  cap.config.state = {
    challengesList: {
      [challenge.token]: {
        ...challenge,
        expires: challenge.expires,
      },
    },
    tokensList: {},
  };
  return await cap.redeemChallenge({
    token: challenge.token,
    solutions,
  });
}

// ============ Environment ============

interface Env {
  CAP_DB: D1Database;
}

// ============ Worker Entry ============

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // 定期清理过期数据（每次请求触发，简单实现）
    await cleanupExpired(env);

    // CORS 预检
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // ===== POST /api/challenge =====
    if (request.method === "POST" && url.pathname === CHALLENGE_PATH) {
      const challenge = createChallenge();
      
      if (challenge.token) {
        await storeChallenge(env, challenge.token, challenge as ChallengeData);
      }
      
      return new Response(JSON.stringify(challenge), {
        headers: { "Content-Type": "application/json", ...CORS_HEADERS },
      });
    }

    // ===== POST /api/redeem =====
    if (request.method === "POST" && url.pathname === REDEEM_PATH) {
      let body: { token?: string; solutions?: number[] };
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ success: false, error: "Invalid request body" }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        });
      }

      const { token, solutions } = body ?? {};
      if (!token || !solutions || !Array.isArray(solutions)) {
        return new Response(JSON.stringify({ success: false, error: "Missing token or solutions" }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        });
      }

      const challenge = await getChallenge(env, token);
      if (!challenge) {
        return new Response(JSON.stringify({ success: false, error: "Challenge not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        });
      }

      if (challenge.expires < Date.now()) {
        await deleteChallenge(env, token);
        return new Response(JSON.stringify({ success: false, error: "Challenge expired" }), {
          status: 410,
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        });
      }

      const result = await verifyChallengeSolution(challenge, solutions);

      if (result.success && result.token && result.expires) {
        const tokenHash = await hashToken(result.token);
        await deleteChallenge(env, token);
        await storeToken(env, tokenHash, result.expires);
      }

      return new Response(JSON.stringify(result), {
        headers: { "Content-Type": "application/json", ...CORS_HEADERS },
      });
    }

    // ===== POST /api/validate =====
    if (request.method === "POST" && url.pathname === VALIDATE_PATH) {
      let body: { token?: string; keepToken?: boolean };
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ success: false, error: "Invalid request body" }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        });
      }

      const { token, keepToken } = body ?? {};
      if (!token) {
        return new Response(JSON.stringify({ success: false, error: "Missing token" }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        });
      }

      const tokenHash = await hashToken(token);
      const stored = await getToken(env, tokenHash);

      if (!stored) {
        return new Response(JSON.stringify({ success: false, error: "Token not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        });
      }

      if (stored.expires < Date.now()) {
        await deleteToken(env, tokenHash);
        return new Response(JSON.stringify({ success: false, error: "Token expired" }), {
          status: 410,
          headers: { "Content-Type": "application/json", ...CORS_HEADERS },
        });
      }

      if (!keepToken) {
        await deleteToken(env, tokenHash);
      }

      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json", ...CORS_HEADERS },
      });
    }

    return new Response("Not Found", {
      status: 404,
      headers: CORS_HEADERS,
    });
  },
};

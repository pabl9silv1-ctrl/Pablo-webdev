// api/prospeccao.js — Página de Prospecção (PABLO WEB)
// Vercel Serverless Function (Node.js, sem dependências).
// Toda a lógica de login, admin, assinantes, leads, empresas e Pix roda
// aqui, no servidor. O navegador nunca recebe nenhuma chave: o front chama
// esta rota na mesma origem (/api/prospeccao) e o servidor fala com o
// Supabase usando a service_role key das variáveis de ambiente da Vercel.
//
// Variáveis de ambiente (Vercel → Settings → Environment Variables):
//   SUPABASE_URL                 https://vugkqnaektgkfvexoahj.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY    chave secret (sb_secret_...) — NUNCA com
//                                prefixo NEXT_PUBLIC_ e NUNCA no repositório.
//   PROSPECCAO_SETUP_CODE_HASH   SHA-256 hex do código de setup do dono.
//                                Só o hash fica aqui; o código em si o dono
//                                já recebeu fora do repositório.
//   NEXT_PUBLIC_SUPABASE_URL     URL pública do projeto (uso futuro no front).
//
// Tabelas no Supabase: subscribers, leads, companies, settings,
// security_events, auth_attempts, admin_sessions (+ owner_auth, criada pelo
// arquivo supabase-owner-auth.sql que acompanha este deploy).
"use strict";

const crypto = require("crypto");

const OWNER_WHATSAPP = "5585991830920"; // WhatsApp do dono — já é público no site.
const PRICE_CENTS = 1099; // R$ 10,99/mês
const SESSION_HOURS = 12;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;
/* Rate limit em memória (melhor esforço por instância serverless): protege as
   ações públicas contra enumeração e spam sem depender de outro serviço. */
const RATE_WINDOW_MS = 60 * 1000;
const RATE_PUBLIC_PER_MIN = 60;
const RATE_AUTH_PER_MIN = 20;
const RATE_BUCKETS = new Map();
const UF_LIST = ["AC","AL","AP","AM","BA","CE","DF","ES","GO","MA","MT","MS","MG","PA","PB","PR","PE","PI","RJ","RN","RS","RO","RR","SC","SP","SE","TO"];
const LEAD_STATUSES = ["novo","respondeu","pediu_orcamento","negociando","fechou","nao_quer","sem_resposta"];

/* ---------------- util ---------------- */
function send(res, status, obj) {
  res.status(status)
    .setHeader("Content-Type", "application/json; charset=utf-8")
    .setHeader("X-Content-Type-Options", "nosniff")
    .setHeader("Cache-Control", "no-store")
    .setHeader("Referrer-Policy", "no-referrer");
  res.end(JSON.stringify(obj));
}
function clientIp(req) {
  const fwd = req.headers && (req.headers["x-forwarded-for"] || req.headers["x-real-ip"]);
  return String(fwd || "").split(",")[0].trim() || "unknown";
}
function rateLimited(req, action) {
  const auth = action === "claimAdmin" || action === "verifyAdmin";
  const limit = auth ? RATE_AUTH_PER_MIN : RATE_PUBLIC_PER_MIN;
  const key = clientIp(req) + ":" + (auth ? "auth" : "public");
  const now = Date.now();
  let b = RATE_BUCKETS.get(key);
  if (!b || now - b.start > RATE_WINDOW_MS) { b = { start: now, count: 0 }; RATE_BUCKETS.set(key, b); }
  if (RATE_BUCKETS.size > 2000) { for (const [k, v] of RATE_BUCKETS) { if (now - v.start > RATE_WINDOW_MS) RATE_BUCKETS.delete(k); } }
  b.count += 1;
  return b.count > limit;
}
function isValidId(id) {
  return typeof id === "string" && id.length > 0 && id.length <= 64 && /^[A-Za-z0-9-]+$/.test(id);
}
function isValidIsoDate(v) {
  if (v === null || v === "") return true;
  const d = new Date(v);
  return !isNaN(d.getTime()) && /^\d{4}-\d{2}-\d{2}/.test(String(v));
}
function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function onlyDigits(s) {
  return String(s || "").replace(/\D/g, "");
}
/* Normaliza o telefone para o formato com DDI (13 dígitos, ex.: 5585991830920).
   O dono digita 85 99183-0920 (11 dígitos) e o campo do login sugere o número
   sem o 55, então aceita com ou sem DDI: 10 ou 11 dígitos ganham o prefixo 55. */
function normalizePhone(s) {
  const d = onlyDigits(s);
  if (d.length === 13 && d.startsWith("55")) return d;
  if (d.length === 12 && d.startsWith("55")) return d;
  if (d.length === 11 || d.length === 10) return "55" + d;
  return d;
}
function isOwner(phone) {
  return normalizePhone(phone) === OWNER_WHATSAPP;
}
function hashPassword(password, saltHex) {
  const salt = saltHex || crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(String(password), Buffer.from(salt, "hex"), 100000, 32, "sha256").toString("hex");
  return { stored: "pbkdf2$100000$" + salt + "$" + hash, salt };
}
function checkPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
    const iters = parseInt(parts[1], 10);
    const hash = crypto.pbkdf2Sync(String(password), Buffer.from(parts[2], "hex"), iters, 32, "sha256").toString("hex");
    const a = Buffer.from(hash, "hex"), b = Buffer.from(parts[3], "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (e) { return false; }
}

/* ---------------- Supabase REST (service_role, só no servidor) ---------------- */
function sbConfig(res) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    send(res, 503, { error: "not_configured", message: "Banco ainda não configurado na Vercel: faltam SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY nas variáveis de ambiente do projeto." });
    return null;
  }
  return { url: String(url).replace(/\/$/, ""), key };
}
async function sb(cfg, table, method, query, body, prefer) {
  const qs = query ? "?" + new URLSearchParams(query).toString() : "";
  const headers = {
    apikey: cfg.key,
    Authorization: "Bearer " + cfg.key,
    "Content-Type": "application/json",
  };
  if (prefer) headers.Prefer = prefer;
  const r = await fetch(cfg.url + "/rest/v1/" + table + qs, {
    method: method || "GET",
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
  const range = r.headers.get("content-range") || "";
  const total = /\/(\d+|\*)/.test(range) ? range.split("/")[1] : null;
  return { status: r.status, ok: r.ok, data, total };
}
async function sbCount(cfg, table) {
  const r = await sb(cfg, table, "GET", { select: "id", limit: "1" }, null, "count=exact");
  if (r.total && r.total !== "*") return parseInt(r.total, 10);
  return Array.isArray(r.data) ? r.data.length : 0;
}
async function logEvent(cfg, actor, type, detail) {
  try {
    await sb(cfg, "security_events", "POST", null, { actor_phone: actor || null, event_type: type, detail: detail || null });
  } catch (e) { /* log nunca pode quebrar a resposta */ }
}
async function getSettings(cfg) {
  const r = await sb(cfg, "settings", "GET", { select: "*", id: "eq.1" });
  if (r.ok && Array.isArray(r.data) && r.data.length) return r.data[0];
  return { id: 1, price_cents: PRICE_CENTS, whatsapp: OWNER_WHATSAPP, pix_key: null, pix_holder: null };
}

/* ---------------- Pix — payload BR Code (EMV) ---------------- */
function emv(id, value) {
  return id + String(value.length).padStart(2, "0") + value;
}
function crc16(str) {
  let crc = 0xffff;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) {
      crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc.toString(16).toUpperCase().padStart(4, "0");
}
function pixPayload(pixKey, amountCents) {
  const gui = emv("00", "br.gov.bcb.pix") + emv("01", pixKey);
  let p = emv("00", "02") + emv("01", "12");
  p += emv("26", gui);
  p += emv("52", "0000") + emv("53", "986");
  p += emv("54", (amountCents / 100).toFixed(2));
  p += emv("58", "BR") + emv("59", "PABLO WEB") + emv("60", "FORTALEZA");
  p += emv("62", emv("05", "PABLOWEB1099"));
  p += "6304";
  return p + crc16(p);
}

/* ---------------- auth ---------------- */
async function checkLockout(cfg, phone) {
  const since = new Date(Date.now() - LOCKOUT_MINUTES * 60 * 1000).toISOString();
  const r = await sb(cfg, "auth_attempts", "GET", { select: "id", phone: "eq." + phone, success: "eq.false", created_at: "gte." + since });
  const fails = Array.isArray(r.data) ? r.data.length : 0;
  return fails >= MAX_ATTEMPTS;
}
async function recordAttempt(cfg, phone, success) {
  try { await sb(cfg, "auth_attempts", "POST", null, { phone, success }); } catch (e) {}
}
async function getOwnerAuth(cfg) {
  const r = await sb(cfg, "owner_auth", "GET", { select: "*", id: "eq.1" });
  if (r.ok && Array.isArray(r.data) && r.data.length) return r.data[0];
  return null;
}
async function validSession(cfg, token, phone) {
  if (!token) return null;
  const r = await sb(cfg, "admin_sessions", "GET", {
    select: "*", token_hash: "eq." + sha256(token), revoked: "eq.false",
  });
  if (!r.ok || !Array.isArray(r.data) || !r.data.length) return null;
  const s = r.data[0];
  if (new Date(s.expires_at).getTime() < Date.now()) return null;
  if (phone && normalizePhone(s.phone) !== normalizePhone(phone)) return null;
  return s;
}
async function requireAdmin(cfg, body) {
  const token = body.sessionToken;
  const session = await validSession(cfg, token, OWNER_WHATSAPP);
  if (!session) return null;
  return session;
}
/* Busca o assinante pelo número normalizado (com DDI 55). Assinantes
   cadastrados antes da normalização ficaram salvos sem o DDI; nesse caso
   busca pelo formato antigo e regrava normalizado (autocura). */
async function findSubscriber(cfg, phone) {
  const norm = normalizePhone(phone);
  let r = await sb(cfg, "subscribers", "GET", { select: "*", phone: "eq." + norm });
  if (r.ok && Array.isArray(r.data) && r.data.length) return r.data[0];
  const legacy = onlyDigits(phone);
  if (legacy && legacy !== norm) {
    r = await sb(cfg, "subscribers", "GET", { select: "*", phone: "eq." + legacy });
    if (r.ok && Array.isArray(r.data) && r.data.length) {
      const row = r.data[0];
      try { await sb(cfg, "subscribers", "PATCH", { phone: "eq." + legacy }, { phone: norm }); } catch (e) {}
      row.phone = norm;
      return row;
    }
  }
  return null;
}
async function subscriberAccess(cfg, phone) {
  phone = normalizePhone(phone);
  if (!phone) return { access: "not_found" };
  if (isOwner(phone)) return { access: "owner" };
  const s = await findSubscriber(cfg, phone);
  if (!s) return { access: "not_found" };
  if (s.status === "blocked") return { access: "blocked", subscriber: s };
  if (s.status !== "active") return { access: "pending", subscriber: s };
  if (s.access_until && new Date(s.access_until).getTime() < Date.now()) return { access: "expired", subscriber: s };
  return { access: "active", subscriber: s };
}

/* ---------------- handler ---------------- */
module.exports = async function handler(req, res) {
  /* Sem CORS aberto: o front chama esta rota na mesma origem, então nenhum
     site de terceiros precisa — e não deve — chamar a API pelo navegador. */
  if (req.method === "OPTIONS") return res.status(204).end();

  let body = {};
  if (req.method === "POST") {
    try { body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {}); }
    catch (e) { return send(res, 400, { error: "bad_json" }); }
  }
  const action = (req.query && req.query.action) || body.action || "";
  if (!action) return send(res, 400, { error: "missing_action" });
  if (rateLimited(req, action)) return send(res, 429, { error: "rate_limited", message: "Muitas requisições. Aguarde um minuto e tente de novo." });

  const cfg = sbConfig(res);
  if (!cfg) return; // 503 já enviado

  try {
    /* ---------- público ---------- */
    if (action === "publicInfo") {
      const s = await getSettings(cfg);
      return send(res, 200, {
        price_cents: s.price_cents || PRICE_CENTS,
        whatsapp: s.whatsapp || OWNER_WHATSAPP,
        pix_configured: !!s.pix_key,
        pix_holder: s.pix_holder || null,
      });
    }
    if (action === "pixPayload") {
      const s = await getSettings(cfg);
      if (!s.pix_key) return send(res, 400, { error: "pix_not_configured", message: "Chave Pix ainda não cadastrada pelo dono em Admin → Configurações de recebimento." });
      return send(res, 200, {
        payload: pixPayload(s.pix_key, s.price_cents || PRICE_CENTS),
        pix_key: s.pix_key,
        pix_holder: s.pix_holder || "PABLO WEB",
        amount_cents: s.price_cents || PRICE_CENTS,
        whatsapp: s.whatsapp || OWNER_WHATSAPP,
      });
    }
    if (action === "requestAccess") {
      const name = String(body.name || "").trim().slice(0, 80);
      const phone = normalizePhone(body.whatsapp || body.phone);
      if (!name || phone.length < 12) return send(res, 400, { error: "invalid_data", message: "Informe seu nome e um WhatsApp válido." });
      const existing = await findSubscriber(cfg, phone);
      if (existing) {
        return send(res, 200, { ok: true, status: existing.status, message: "Você já tem um pedido com esse número." });
      }
      const ins = await sb(cfg, "subscribers", "POST", null, { phone, name, status: "pending" }, "return=representation");
      if (!ins.ok) return send(res, 500, { error: "db_error" });
      await logEvent(cfg, phone, "access_requested", name);
      return send(res, 200, { ok: true, status: "pending" });
    }
    if (action === "lookupAccess") {
      const a = await subscriberAccess(cfg, body.whatsapp || body.phone);
      return send(res, 200, { access: a.access });
    }

    /* ---------- admin: primeiro acesso ---------- */
    if (action === "claimAdmin") {
      const phone = normalizePhone(body.whatsapp);
      const code = String(body.code || "").trim();
      const password = String(body.password || "");
      if (!isOwner(phone)) return send(res, 403, { error: "not_owner", message: "Este número não é o do dono. Use o WhatsApp do dono com DDI: 5585991830920." });
      if (password.length < 8) return send(res, 400, { error: "weak_password", message: "A senha precisa de pelo menos 8 caracteres." });
      if (await checkLockout(cfg, phone)) return send(res, 429, { error: "locked", message: "Muitas tentativas. Aguarde 15 minutos." });
      const setupHash = process.env.PROSPECCAO_SETUP_CODE_HASH;
      const row = await getOwnerAuth(cfg);
      if (row && row.password_hash) return send(res, 400, { error: "already_claimed", message: "O admin já foi configurado. Entre com sua senha ou use a troca de senha." });
      const expected = row && row.setup_code_hash ? row.setup_code_hash : setupHash;
      if (!expected || sha256(code) !== expected) {
        await recordAttempt(cfg, phone, false);
        return send(res, 403, { error: "bad_code", message: "Código de setup inválido." });
      }
      const { stored } = hashPassword(password);
      if (row) {
        await sb(cfg, "owner_auth", "PATCH", { id: "eq.1" }, { password_hash: stored, setup_code_hash: null });
      } else {
        await sb(cfg, "owner_auth", "POST", null, { id: 1, password_hash: stored, setup_code_hash: null });
      }
      await recordAttempt(cfg, phone, true);
      await logEvent(cfg, phone, "admin_claimed", "Senha do dono criada");
      return send(res, 200, { ok: true });
    }
    if (action === "verifyAdmin") {
      const phone = normalizePhone(body.whatsapp);
      const password = String(body.password || "");
      if (!isOwner(phone)) return send(res, 403, { error: "not_owner", message: "Este número não é o do dono. Use o WhatsApp do dono com DDI: 5585991830920." });
      if (await checkLockout(cfg, phone)) return send(res, 429, { error: "locked", message: "Número bloqueado por 15 minutos após 5 senhas erradas." });
      const row = await getOwnerAuth(cfg);
      if (!row || !row.password_hash) return send(res, 400, { error: "not_claimed", message: "Admin ainda não configurado. Use o código de setup primeiro." });
      if (!checkPassword(password, row.password_hash)) {
        await recordAttempt(cfg, phone, false);
        await logEvent(cfg, phone, "login_failed", "Senha incorreta");
        return send(res, 403, { error: "bad_password", message: "Senha incorreta." });
      }
      await recordAttempt(cfg, phone, true);
      const token = crypto.randomBytes(32).toString("hex");
      const expires = new Date(Date.now() + SESSION_HOURS * 3600 * 1000).toISOString();
      await sb(cfg, "admin_sessions", "POST", null, { phone, token_hash: sha256(token), expires_at: expires, revoked: false });
      await logEvent(cfg, phone, "login_ok", "Login do dono");
      return send(res, 200, { ok: true, sessionToken: token, expires_at: expires });
    }
    if (action === "authMe") {
      const s = await validSession(cfg, body.sessionToken, body.whatsapp);
      return send(res, 200, { ok: !!s, owner: !!s && isOwner(s.phone) });
    }
    if (action === "logoutAdmin") {
      if (body.sessionToken) {
        await sb(cfg, "admin_sessions", "PATCH", { token_hash: "eq." + sha256(body.sessionToken) }, { revoked: true });
      }
      return send(res, 200, { ok: true });
    }

    /* ---------- ferramenta do assinante ---------- */
    if (action === "listDirectory") {
      const a = await subscriberAccess(cfg, body.whatsapp);
      if (a.access !== "active" && a.access !== "owner") return send(res, 403, { error: "no_access", access: a.access });
      const q = { select: "*", has_website: "eq.false", order: "state.asc,name.asc", limit: "500" };
      if (body.state) q.state = "eq." + String(body.state).toUpperCase();
      const r = await sb(cfg, "companies", "GET", q);
      if (!r.ok) return send(res, 500, { error: "db_error" });
      return send(res, 200, { ok: true, companies: r.data || [] });
    }
    if (action === "addLead" || action === "listLeads" || action === "updateLead" || action === "deleteLead") {
      const phone = normalizePhone(body.whatsapp);
      const a = await subscriberAccess(cfg, phone);
      if (a.access !== "active" && a.access !== "owner") return send(res, 403, { error: "no_access", access: a.access });
      if (action === "listLeads") {
        /* Leads antigos podem estar salvos sem o DDI; busca nos dois formatos. */
        const legacy = onlyDigits(body.whatsapp);
        const q = { select: "*", order: "created_at.desc" };
        if (legacy && legacy !== phone) q.or = "(owner_phone.eq." + phone + ",owner_phone.eq." + legacy + ")";
        else q.owner_phone = "eq." + phone;
        const r = await sb(cfg, "leads", "GET", q);
        return send(res, 200, { ok: true, leads: r.data || [] });
      }
      if (action === "addLead") {
        const name = String(body.company_name || body.companyName || "").trim().slice(0, 120);
        const uf = String(body.state || "").trim().toUpperCase();
        if (!name) return send(res, 400, { error: "invalid_data" });
        if (uf && !UF_LIST.includes(uf)) return send(res, 400, { error: "invalid_data", message: "Estado (UF) inválido." });
        const ins = await sb(cfg, "leads", "POST", null, {
          owner_phone: phone, company_name: name,
          niche: String(body.niche || "").slice(0, 60) || null,
          city: String(body.city || "").slice(0, 80) || null,
          state: uf || null,
          phone: normalizePhone(body.phone) || null,
          status: "novo", notes: String(body.notes || "").slice(0, 500) || null,
        }, "return=representation");
        if (!ins.ok) return send(res, 500, { error: "db_error" });
        return send(res, 200, { ok: true, lead: ins.data && ins.data[0] });
      }
      if (action === "updateLead") {
        if (!isValidId(body.id)) return send(res, 400, { error: "invalid_data" });
        const patch = {};
        if (body.status !== undefined) {
          if (!LEAD_STATUSES.includes(body.status)) return send(res, 400, { error: "invalid_data", message: "Status de lead inválido." });
          patch.status = body.status;
        }
        if (body.notes !== undefined) patch.notes = String(body.notes).slice(0, 500);
        if (body.follow_up_at !== undefined) {
          if (!isValidIsoDate(body.follow_up_at)) return send(res, 400, { error: "invalid_data", message: "Data de follow-up inválida." });
          patch.follow_up_at = body.follow_up_at || null;
        }
        /* Posse checada pelo dono do lead (número normalizado), não pelo filtro da query. */
        const own = await sb(cfg, "leads", "GET", { select: "id,owner_phone", id: "eq." + body.id });
        if (!own.ok || !own.data || !own.data.length || normalizePhone(own.data[0].owner_phone) !== phone) return send(res, 404, { error: "not_found" });
        await sb(cfg, "leads", "PATCH", { id: "eq." + body.id }, patch);
        return send(res, 200, { ok: true });
      }
      if (action === "deleteLead") {
        if (!isValidId(body.id)) return send(res, 400, { error: "invalid_data" });
        const own = await sb(cfg, "leads", "GET", { select: "id,owner_phone", id: "eq." + body.id });
        if (!own.ok || !own.data || !own.data.length || normalizePhone(own.data[0].owner_phone) !== phone) return send(res, 404, { error: "not_found" });
        await sb(cfg, "leads", "DELETE", { id: "eq." + body.id });
        return send(res, 200, { ok: true });
      }
    }

    /* ---------- admin ---------- */
    const admin = await requireAdmin(cfg, body);
    if (["adminOverview", "adminSetSubscriber", "adminUnlockNumber", "adminUpdateSettings", "getSecurityOverview", "getSupabaseStatus", "changeAdminPin", "revokeAllSessions", "adminExport"].includes(action) && !admin) {
      return send(res, 401, { error: "unauthorized", message: "Sessão de admin inválida ou expirada. Entre novamente." });
    }
    if (action === "adminOverview") {
      const subs = await sb(cfg, "subscribers", "GET", { select: "*", order: "created_at.desc", limit: "500" });
      const list = subs.data || [];
      const now = Date.now();
      const stats = {
        total: list.length,
        active: list.filter(s => s.status === "active" && (!s.access_until || new Date(s.access_until).getTime() > now)).length,
        pending: list.filter(s => s.status === "pending").length,
        blocked: list.filter(s => s.status === "blocked").length,
        expired: list.filter(s => s.status === "active" && s.access_until && new Date(s.access_until).getTime() <= now).length,
      };
      stats.monthly_revenue_cents = stats.active * PRICE_CENTS;
      const settings = await getSettings(cfg);
      return send(res, 200, { ok: true, stats, subscribers: list, settings: { pix_key: settings.pix_key, pix_holder: settings.pix_holder, whatsapp: settings.whatsapp, price_cents: settings.price_cents } });
    }
    if (action === "adminSetSubscriber") {
      const phone = normalizePhone(body.phone);
      const op = body.op;
      if (!phone || !["activate", "renew", "block", "unblock", "remove"].includes(op)) return send(res, 400, { error: "invalid_data" });
      if (op === "remove") {
        await sb(cfg, "subscribers", "DELETE", { phone: "eq." + phone });
      } else if (op === "activate") {
        const until = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
        await sb(cfg, "subscribers", "PATCH", { phone: "eq." + phone }, { status: "active", access_until: until });
      } else if (op === "renew") {
        const cur = await sb(cfg, "subscribers", "GET", { select: "access_until", phone: "eq." + phone });
        const base = (cur.data && cur.data[0] && cur.data[0].access_until && new Date(cur.data[0].access_until).getTime() > Date.now())
          ? new Date(cur.data[0].access_until).getTime() : Date.now();
        await sb(cfg, "subscribers", "PATCH", { phone: "eq." + phone }, { status: "active", access_until: new Date(base + 30 * 24 * 3600 * 1000).toISOString() });
      } else if (op === "block") {
        await sb(cfg, "subscribers", "PATCH", { phone: "eq." + phone }, { status: "blocked" });
      } else if (op === "unblock") {
        await sb(cfg, "subscribers", "PATCH", { phone: "eq." + phone }, { status: "pending" });
      }
      await logEvent(cfg, OWNER_WHATSAPP, "subscriber_" + op, phone);
      return send(res, 200, { ok: true });
    }
    if (action === "adminUnlockNumber") {
      const phone = normalizePhone(body.phone || body.whatsapp);
      if (!phone) return send(res, 400, { error: "invalid_data" });
      const legacy = onlyDigits(body.phone || body.whatsapp);
      await sb(cfg, "auth_attempts", "DELETE", { phone: "eq." + phone, success: "eq.false" });
      if (legacy && legacy !== phone) await sb(cfg, "auth_attempts", "DELETE", { phone: "eq." + legacy, success: "eq.false" });
      await logEvent(cfg, OWNER_WHATSAPP, "number_unlocked", phone);
      return send(res, 200, { ok: true });
    }
    if (action === "adminUpdateSettings") {
      const patch = {};
      if (body.pix_key !== undefined) patch.pix_key = String(body.pix_key || "").trim() || null;
      if (body.pix_holder !== undefined) patch.pix_holder = String(body.pix_holder || "").trim() || null;
      if (body.whatsapp !== undefined) patch.whatsapp = normalizePhone(body.whatsapp) || OWNER_WHATSAPP;
      await sb(cfg, "settings", "PATCH", { id: "eq.1" }, patch);
      await logEvent(cfg, OWNER_WHATSAPP, "settings_updated", "Configurações de recebimento atualizadas");
      return send(res, 200, { ok: true });
    }
    if (action === "getSecurityOverview") {
      const counts = {};
      for (const t of ["subscribers", "leads", "companies", "settings", "security_events", "auth_attempts", "admin_sessions"]) {
        counts[t] = await sbCount(cfg, t);
      }
      const events = await sb(cfg, "security_events", "GET", { select: "*", order: "created_at.desc", limit: "20" });
      return send(res, 200, { ok: true, counts, events: events.data || [] });
    }
    if (action === "getSupabaseStatus") {
      const counts = {};
      for (const t of ["subscribers", "leads", "companies", "settings", "security_events", "auth_attempts", "admin_sessions"]) {
        counts[t] = await sbCount(cfg, t);
      }
      return send(res, 200, { ok: true, configured: true, url: cfg.url, tables: counts });
    }
    if (action === "adminExport") {
      /* Backup manual do banco (só o dono, com sessão válida). O plano Free do
         Supabase não tem backup automático — este export é o caminho do dono
         para guardar uma cópia fora do Supabase até migrar para o Pro. */
      const subs = await sb(cfg, "subscribers", "GET", { select: "*", order: "created_at.desc", limit: "1000" });
      const leads = await sb(cfg, "leads", "GET", { select: "*", order: "created_at.desc", limit: "1000" });
      const companies = await sb(cfg, "companies", "GET", { select: "*", order: "state.asc,name.asc", limit: "1000" });
      const settings = await getSettings(cfg);
      await logEvent(cfg, OWNER_WHATSAPP, "backup_exported", "Exportação manual do banco (admin)");
      return send(res, 200, { ok: true, exported_at: new Date().toISOString(), subscribers: subs.data || [], leads: leads.data || [], companies: companies.data || [], settings });
    }
    if (action === "changeAdminPin") {
      const row = await getOwnerAuth(cfg);
      if (!row || !checkPassword(String(body.currentPassword || ""), row.password_hash)) return send(res, 403, { error: "bad_password" });
      if (String(body.newPassword || "").length < 8) return send(res, 400, { error: "weak_password" });
      const { stored } = hashPassword(body.newPassword);
      await sb(cfg, "owner_auth", "PATCH", { id: "eq.1" }, { password_hash: stored });
      await sb(cfg, "admin_sessions", "PATCH", { phone: "eq." + OWNER_WHATSAPP }, { revoked: true });
      const token = crypto.randomBytes(32).toString("hex");
      const expires = new Date(Date.now() + SESSION_HOURS * 3600 * 1000).toISOString();
      await sb(cfg, "admin_sessions", "POST", null, { phone: OWNER_WHATSAPP, token_hash: sha256(token), expires_at: expires, revoked: false });
      await logEvent(cfg, OWNER_WHATSAPP, "password_changed", "Senha do admin trocada");
      return send(res, 200, { ok: true, sessionToken: token, expires_at: expires });
    }
    if (action === "revokeAllSessions") {
      await sb(cfg, "admin_sessions", "PATCH", { phone: "eq." + OWNER_WHATSAPP }, { revoked: true });
      const token = crypto.randomBytes(32).toString("hex");
      const expires = new Date(Date.now() + SESSION_HOURS * 3600 * 1000).toISOString();
      await sb(cfg, "admin_sessions", "POST", null, { phone: OWNER_WHATSAPP, token_hash: sha256(token), expires_at: expires, revoked: false });
      return send(res, 200, { ok: true, sessionToken: token, expires_at: expires });
    }

    return send(res, 400, { error: "unknown_action", action });
  } catch (e) {
    /* Mensagem genérica de propósito: detalhe interno nunca volta ao cliente. */
    return send(res, 500, { error: "server_error", message: "Erro interno. Tente de novo em instantes." });
  }
};

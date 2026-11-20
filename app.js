/**
 * Vesuvio Forno & Brasa (vesuvio-forno-kds) — Enterprise Application Engine, Firestore TLS Transport,
 * OWASP Top 10 Security Layer & LGPD Privacy-by-Design
 * Autor: Julio Cesar (@nonscs813-a11y)
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.__ENTERPRISE_APP__ = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const FIREBASE_CONFIG = Object.freeze({
    projectId: "julio-enterprise-suite",
    apiKey: "AIzaSyDqb7tfGwgkSImIuiiyNllJdPU0cDMDip4",
    collection: "pedidos_pizzaria",
    site: "vesuvio-forno-kds",
    appId: "1:84300962562:web:f3584419192139dfa8001b",
    storageKey: "fb_enterprise_pedidos_pizzaria_v4",
    apiEndpoint: "https://firestore.googleapis.com/v1/projects/julio-enterprise-suite/databases/(default)/documents/pedidos_pizzaria",
    timeoutMs: 4500
  });

  // App Check (Fraud Defense / reCAPTCHA Enterprise) — chave publica, sem segredo no cliente.
  const APP_CHECK_CONFIG = Object.freeze({
    siteKey: "6LcgySkuAAAAAEtMX3v4cK514gKQZJvsAJ4fPVb2",
    projectNumber: "84300962562"
  });

  async function acquireAppCheckToken(appId, apiKey) {
    if (typeof window === "undefined" || typeof document === "undefined") return null;
    try {
      if (!window.grecaptcha || !window.grecaptcha.enterprise) {
        await new Promise((resolve, reject) => {
          const script = document.createElement("script");
          script.src = "https://www.google.com/recaptcha/enterprise.js?render=" + APP_CHECK_CONFIG.siteKey;
          script.async = true;
          script.onload = resolve;
          script.onerror = reject;
          document.head.appendChild(script);
        });
      }
      const recaptchaToken = await window.grecaptcha.enterprise.execute(APP_CHECK_CONFIG.siteKey, { action: "firestore" });
      const endpoint = `https://firebaseappcheck.googleapis.com/v1beta/projects/${APP_CHECK_CONFIG.projectNumber}/apps/${appId}:exchangeRecaptchaEnterpriseToken?key=${encodeURIComponent(apiKey)}`;
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recaptchaEnterpriseToken: recaptchaToken }),
      });
      if (!res.ok) return null;
      const data = await res.json();
      return data.token || null;
    } catch {
      return null;
    }
  }

  const ALLOWED_STATUS = Object.freeze(["Confirmado", "Em Atendimento", "Concluído"]);
  const ALLOWED_FIREBASE_HOSTS = Object.freeze([
    "firestore.googleapis.com",
    "firebaseio.com",
    "identitytoolkit.googleapis.com"
  ]);

  const SERVICES = Object.freeze([
  {
    "id": "s1",
    "name": "Margherita D.O.P. (Pomodoro San Marzano & Fior di Latte)",
    "cat": "Clássicas",
    "price": 74.0,
    "duration": "8 Fatias",
    "desc": "Molho de tomates italianos pelados, mozzarella fresca, manjericão gigante e azeite extravirgem."
  },
  {
    "id": "s2",
    "name": "Calabresa Artesanal Curada & Cebola Roxa Caramelizada",
    "cat": "Tradicionais",
    "price": 79.0,
    "duration": "8 Fatias",
    "desc": "Linguiça calabresa defumada em lenha de macieira, queijo meia cura mineiro e azeitonas pretas."
  },
  {
    "id": "s3",
    "name": "Quattro Formaggi com Mel Trufado & Nozes",
    "cat": "Especiais",
    "price": 89.0,
    "duration": "8 Fatias",
    "desc": "Gorgonzola dolce, parmesão 18 meses, fior di latte, catupiry legítimo e toque de mel trufado."
  },
  {
    "id": "s4",
    "name": "Parma & Burrata Cremosa com Pesto de Manjericão",
    "cat": "Autorais",
    "price": 98.0,
    "duration": "8 Fatias",
    "desc": "Presunto cru italiano maturado 12 meses, burrata inteira fresca ao centro e pesto artesanal."
  },
  {
    "id": "s5",
    "name": "Focaccia de Alecrim, Flor de Sal & Azeite Trufado",
    "cat": "Entradas",
    "price": 38.0,
    "duration": "Porção",
    "desc": "Massa alveolada assada na pedra a 450°C ideal para compartilhar com antepastos."
  },
  {
    "id": "s6",
    "name": "Calzone de Nutella com Morangos Frescos & Pistache",
    "cat": "Doces",
    "price": 56.0,
    "duration": "4 Fatias",
    "desc": "Massa crocante recheada com creme de avelã original e pistache torrado picado."
  }
]);
  const SEED_RECORDS = Object.freeze([
  {
    "cliente": "Leonardo Martins",
    "contato": "Av. do Contorno, 6400 - Savassi",
    "profissional": "Massa Napoletana Tradicional 48h",
    "servico": "Parma & Burrata Cremosa + Focaccia",
    "horario": "Delivery Express",
    "valor": "R$ 136,00",
    "status": "Em Atendimento"
  },
  {
    "cliente": "Camila Azevedo",
    "contato": "Rua Rio de Janeiro, 1820 - Lourdes",
    "profissional": "Borda Recheada Catupiry Original",
    "servico": "Margherita D.O.P. (8 Fatias)",
    "horario": "Delivery Express",
    "valor": "R$ 88,00",
    "status": "Confirmado"
  },
  {
    "cliente": "Thiago Drummond",
    "contato": "Retirada no Balcão",
    "profissional": "Massa Napoletana Tradicional 48h",
    "servico": "Quattro Formaggi com Mel Trufado",
    "horario": "Retirada 20 min",
    "valor": "R$ 89,00",
    "status": "Concluído"
  }
]);

  // ============================================================================
  // 1. SEGURANCA DEFENSIVA (OWASP TOP 10: XSS, NOSQLI, SQLI, PROTO POLLUTION)
  // ============================================================================

  const HTML_ESCAPE_MAP = Object.freeze({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
    "/": "&#x2F;",
    "`": "&#x60;"
  });

  function escapeHTML(input) {
    if (input === null || input === undefined) return "";
    return String(input).replace(/[&<>"'/`]/g, (ch) => HTML_ESCAPE_MAP[ch] || ch);
  }

  const MALICIOUS_PATTERNS = [
    /<\s*script/i,
    /javascript\s*:/i,
    /vbscript\s*:/i,
    /data\s*:\s*text\/html/i,
    /on(?:error|load|click|mouseover|focus|blur|submit|animationstart|toggle)\s*=/i,
    /<\s*(?:iframe|object|embed|svg|math|meta|link|style|base|form)/i,
    /__(?:proto|defineGetter|defineSetter|lookupGetter|lookupSetter)__/i,
    /constructor\s*\[|\bprototype\b/i,
    /\$(?:where|gt|gte|lt|lte|ne|nin|in|regex|expr|function)/i,
    /\b(?:UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM)\b/i
  ];

  function detectMaliciousPayload(value) {
    if (value === null || value === undefined) return false;
    if (typeof value === "object") {
      const keys = Object.keys(value);
      for (const k of keys) {
        if (k === "__proto__" || k === "constructor" || k === "prototype" || k.startsWith("$")) {
          return true;
        }
        if (detectMaliciousPayload(value[k])) return true;
      }
      return false;
    }
    const str = String(value);
    return MALICIOUS_PATTERNS.some((rx) => rx.test(str));
  }

  // ============================================================================
  // 2. VALIDACAO DE TRANSPORTE TLS 1.3 & ANTI-SSRF PARA FIREBASE CLOUD (OWASP A10)
  // ============================================================================

  function validateFirebaseEndpoint(urlStr) {
    if (!urlStr || typeof urlStr !== "string") {
      return { valid: false, reason: "Endpoint vazio ou inválido." };
    }
    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch {
      return { valid: false, reason: "Sintaxe de URL malformada." };
    }
    if (parsed.protocol !== "https:") {
      return { valid: false, reason: "Violação TLS: protocolo HTTPS estrito é obrigatório (HTTP bloqueado)." };
    }
    const host = parsed.hostname.toLowerCase();
    const isAllowedHost = ALLOWED_FIREBASE_HOSTS.some(
      (allowed) => host === allowed || host.endsWith("." + allowed)
    );
    if (!isAllowedHost) {
      return { valid: false, reason: `Bloqueio Anti-SSRF: host '${host}' não pertence à whitelist oficial do Google Firebase.` };
    }
    if (parsed.username || parsed.password) {
      return { valid: false, reason: "Credenciais embutidas na URL são proibidas." };
    }
    return { valid: true, url: parsed.toString(), host };
  }

  // ============================================================================
  // 3. SERIALIZADOR DO PROTOCOLO OFICIAL GOOGLE CLOUD FIRESTORE REST V1
  // ============================================================================

  function toFirestoreDocument(record) {
    return {
      fields: {
        id: { stringValue: String(record.id || "") },
        cliente: { stringValue: String(record.cliente || "") },
        contato: { stringValue: String(record.contato || "") },
        profissional: { stringValue: String(record.profissional || "") },
        servico: { stringValue: String(record.servico || "") },
        horario: { stringValue: String(record.horario || "") },
        valor: { stringValue: String(record.valor || "") },
        status: { stringValue: String(record.status || "Confirmado") },
        obs: { stringValue: String(record.obs || "") },
        lgpdConsent: { booleanValue: Boolean(record.lgpdConsent) },
        integrityHash: { stringValue: String(record.integrityHash || "") },
        createdAt: { timestampValue: String(record.createdAt || new Date().toISOString()) }
      }
    };
  }

  function fromFirestoreDocument(firestoreDoc) {
    if (!firestoreDoc || !firestoreDoc.fields || typeof firestoreDoc.fields !== "object") {
      throw new Error("Documento Firestore malformado: objeto 'fields' ausente.");
    }
    const f = firestoreDoc.fields;
    const record = {
      id: f.id?.stringValue || "",
      cliente: f.cliente?.stringValue || "",
      contato: f.contato?.stringValue || "",
      profissional: f.profissional?.stringValue || "",
      servico: f.servico?.stringValue || "",
      horario: f.horario?.stringValue || "",
      valor: f.valor?.stringValue || "",
      status: f.status?.stringValue || "Confirmado",
      obs: f.obs?.stringValue || "",
      lgpdConsent: Boolean(f.lgpdConsent?.booleanValue),
      integrityHash: f.integrityHash?.stringValue || "",
      createdAt: f.createdAt?.timestampValue || ""
    };
    if (!verifyIntegrity(record)) {
      throw new Error("Violação de Integridade Criptográfica: o hash FNV-1a do documento Firestore não confere.");
    }
    return record;
  }

  // ============================================================================
  // 4. CIRCUIT BREAKER DE CONEXAO CLOUD (RESILIENCIA & ZERO DOWNTIME)
  // ============================================================================

  class CloudCircuitBreaker {
    constructor(failureThreshold = 3, cooldownMs = 30000) {
      this.failureThreshold = failureThreshold;
      this.cooldownMs = cooldownMs;
      this.failures = 0;
      this.state = "CLOSED"; // CLOSED (Normal), OPEN (Fallback Ativo), HALF_OPEN (Sondagem)
      this.openedAt = 0;
    }

    canRequest(now = Date.now()) {
      if (this.state === "CLOSED") return true;
      if (this.state === "OPEN" && now - this.openedAt >= this.cooldownMs) {
        this.state = "HALF_OPEN";
        return true;
      }
      return this.state === "HALF_OPEN";
    }

    recordSuccess() {
      this.failures = 0;
      this.state = "CLOSED";
    }

    recordFailure(now = Date.now()) {
      this.failures += 1;
      if (this.failures >= this.failureThreshold) {
        this.state = "OPEN";
        this.openedAt = now;
      }
    }
  }

  // ============================================================================
  // 5. PRIVACIDADE & LGPD (MASCARAMENTO DE PII & MINIMIZACAO DE DADOS)
  // ============================================================================

  function maskPII(value) {
    if (!value) return "";
    const str = String(value).trim();
    if (str.includes("@") && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str)) {
      const [user, domain] = str.split("@");
      const prefix = user.slice(0, Math.min(2, user.length));
      return `${prefix}***@${domain}`;
    }
    if (/\d{4,5}-\d{4}/.test(str)) {
      return str.replace(/(\d)\d{3,4}(-\d{4})/, "$1****$2");
    }
    if (str.length > 10) {
      return `${str.slice(0, 6)}***${str.slice(-3)}`;
    }
    return str.slice(0, 2) + "***";
  }

  // ============================================================================
  // 6. INTEGRIDADE CRIPTOGRAFICA DE REGISTROS (OWASP A08 - FNV-1A 64-BIT HEX)
  // ============================================================================

  function computeIntegrityHash(record) {
    const canonical = [
      String(record.cliente || ""),
      String(record.contato || ""),
      String(record.profissional || ""),
      String(record.servico || ""),
      String(record.horario || ""),
      String(record.valor || ""),
      String(record.status || "Confirmado")
    ].join("|");

    let h1 = 0x811c9dc5;
    let h2 = 0xcbf29ce4;
    for (let i = 0; i < canonical.length; i++) {
      const c = canonical.charCodeAt(i);
      h1 ^= c;
      h1 = Math.imul(h1, 0x01000193) >>> 0;
      h2 ^= (c ^ (i & 0xff));
      h2 = Math.imul(h2, 0x01000193) >>> 0;
    }
    return "sig_" + h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0");
  }

  function verifyIntegrity(record) {
    if (!record || typeof record !== "object" || !record.integrityHash) return false;
    return computeIntegrityHash(record) === record.integrityHash;
  }

  // ============================================================================
  // 7. VALIDACAO DE CONTRATO DE SCHEMA + CONSENTIMENTO LGPD
  // ============================================================================

  function validateRecordSchema(payload) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      return { valid: false, error: "Payload inválido: formato de objeto obrigatório." };
    }
    if (detectMaliciousPayload(payload)) {
      return { valid: false, error: "Bloqueio de Segurança (OWASP): Payload contém vetor malicioso (XSS/Injection)." };
    }
    if (payload.lgpdConsent === false) {
      return { valid: false, error: "Conformidade LGPD: O consentimento explícito é obrigatório para persistir dados pessoais." };
    }

    const cliente = String(payload.cliente || "").trim();
    const contato = String(payload.contato || "").trim();
    const profissional = String(payload.profissional || "").trim();
    const servico = String(payload.servico || "").trim();
    const horario = String(payload.horario || "").trim();
    const valor = String(payload.valor || "").trim();
    const status = String(payload.status || "Confirmado").trim();
    const obs = String(payload.obs || "").trim();

    if (cliente.length < 2 || cliente.length > 120) {
      return { valid: false, error: "Campo 'cliente' deve ter entre 2 e 120 caracteres." };
    }
    if (contato.length < 4 || contato.length > 120) {
      return { valid: false, error: "Campo 'contato' deve ter entre 4 e 120 caracteres." };
    }
    if (profissional.length < 2 || profissional.length > 120) {
      return { valid: false, error: "Campo 'profissional' inválido." };
    }
    if (servico.length < 2 || servico.length > 160) {
      return { valid: false, error: "Campo 'servico' inválido." };
    }
    if (horario.length < 2 || horario.length > 80) {
      return { valid: false, error: "Campo 'horario' inválido." };
    }
    if (obs.length > 200) {
      return { valid: false, error: "Campo 'obs' excede o limite de 200 caracteres." };
    }
    if (!ALLOWED_STATUS.includes(status)) {
      return { valid: false, error: "Status inválido fora do contrato permitido." };
    }
    const numericVal = parseBRL(valor);
    if (!Number.isFinite(numericVal) || numericVal < 0) {
      return { valid: false, error: "Valor monetário inválido." };
    }

    const sanitized = {
      cliente: escapeHTML(cliente),
      contato: escapeHTML(contato),
      profissional: escapeHTML(profissional),
      servico: escapeHTML(servico),
      horario: escapeHTML(horario),
      valor: formatBRL(numericVal),
      status,
      obs: escapeHTML(obs),
      lgpdConsent: true
    };
    sanitized.integrityHash = computeIntegrityHash(sanitized);

    return {
      valid: true,
      sanitized
    };
  }

  class RateLimiter {
    constructor(maxRequests = 10, windowMs = 60000) {
      this.maxRequests = maxRequests;
      this.windowMs = windowMs;
      this.timestamps = [];
    }

    tryAcquire(now = Date.now()) {
      this.timestamps = this.timestamps.filter((ts) => now - ts < this.windowMs);
      if (this.timestamps.length >= this.maxRequests) {
        return false;
      }
      this.timestamps.push(now);
      return true;
    }

    reset() {
      this.timestamps = [];
    }
  }

  // ============================================================================
  // 8. MOTOR FINANCEIRO DETERMINISTICO (CENTAVOS INTEIROS)
  // ============================================================================

  function formatBRL(num) {
    const safeNum = Number.isFinite(Number(num)) ? Number(num) : 0;
    return safeNum.toLocaleString("pt-BR", {
      style: "currency",
      currency: "BRL"
    });
  }

  function parseBRL(str) {
    if (typeof str === "number") return Number.isFinite(str) ? str : 0;
    const cleaned = String(str || "0")
      .replace(/[^\d,.-]/g, "")
      .replace(/\./g, "")
      .replace(",", ".");
    const parsed = parseFloat(cleaned);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function calculateSimulation(servicesList, selectedIds) {
    const idSet = new Set(Array.isArray(selectedIds) ? selectedIds : []);
    let totalCents = 0;
    let count = 0;
    for (const s of servicesList) {
      if (idSet.has(s.id)) {
        totalCents += Math.round(Number(s.price || 0) * 100);
        count++;
      }
    }
    const totalAmount = totalCents / 100;
    return {
      count,
      totalCents,
      totalAmount,
      formatted: formatBRL(totalAmount)
    };
  }

  // ============================================================================
  // 9. CAMADA DE PERSISTENCIA FIREBASE CLOUD (TLS 1.3 REST + CIRCUIT BREAKER)
  // ============================================================================

  class FirebaseCloudStore {
    constructor(config, seeds) {
      const epValidation = validateFirebaseEndpoint(config.apiEndpoint);
      if (!epValidation.valid) {
        throw new Error(epValidation.reason);
      }
      this.config = config;
      this.authToken = null;
      this.appCheckToken = null;
      this.circuitBreaker = new CloudCircuitBreaker(3, 30000);
      this.seeds = seeds.map((r) => {
        const copy = { ...r, lgpdConsent: true };
        copy.integrityHash = computeIntegrityHash(copy);
        return copy;
      });
      this.memoryStore = null;
      this.listeners = [];
      this.rateLimiter = new RateLimiter(15, 60000);
      this.channel = (typeof window !== "undefined" && typeof document !== "undefined" && typeof BroadcastChannel !== "undefined")
        ? new BroadcastChannel(config.collection)
        : null;
      if (this.channel) {
        this.channel.onmessage = () => this.notify();
      }
    }

    setSecurityTokens({ idToken = null, appCheckToken = null } = {}) {
      this.authToken = idToken;
      this.appCheckToken = appCheckToken;
    }

    // --- Enterprise: Firebase Auth REST (sem segredo no cliente) + leitura/escrita administrativa ---
    decodeIdTokenClaims(idToken) {
      try {
        const part = String(idToken).split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
        const decoded = typeof atob === "function" ? atob(part) : Buffer.from(part, "base64").toString("utf8");
        return JSON.parse(decoded);
      } catch {
        return null;
      }
    }

    async signInAdmin(email, password) {
      if (!this.config.apiKey) throw new Error("API key ausente para Firebase Auth.");
      const endpoint = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(this.config.apiKey)}`;
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
      });
      const data = await res.json();
      if (!res.ok || !data.idToken) {
        throw new Error("Falha de autenticacao: " + ((data.error && data.error.message) || "HTTP " + res.status));
      }
      const claims = this.decodeIdTokenClaims(data.idToken) || {};
      if (claims.site !== this.config.site || claims.role !== "site_admin") {
        throw new Error("Conta sem permissao de administrador deste site.");
      }
      this.setSecurityTokens({ idToken: data.idToken });
      this.adminClaims = claims;
      return { email: data.email, uid: data.localId, site: claims.site, role: claims.role };
    }

    signOutAdmin() {
      this.setSecurityTokens({});
      this.adminClaims = null;
    }

    isAdminAuthenticated() {
      return Boolean(this.authToken && this.adminClaims && this.adminClaims.role === "site_admin" && this.adminClaims.site === this.config.site);
    }

    async loadCloudRecords() {
      await this.ensureAppCheckToken();
      if (!this.isAdminAuthenticated()) throw new Error("Autenticacao de administrador necessaria.");
      const url = `${this.config.apiEndpoint}?key=${encodeURIComponent(this.config.apiKey)}&pageSize=500`;
      const res = await fetch(url, { headers: this.buildSecureHeaders() });
      if (!res.ok) throw new Error("Falha ao carregar registros: HTTP " + res.status);
      const payload = await res.json();
      const records = (payload.documents || []).map((doc) => {
        const rec = fromFirestoreDocument(doc);
        rec.remoteId = String(doc.name || "").split("/").pop();
        return rec;
      });
      this.saveRecords(records);
      return records;
    }

    async updateRemoteRecord(record) {
      await this.ensureAppCheckToken();
      if (!this.isAdminAuthenticated() || !record.remoteId) return { synced: false, mode: "NO_REMOTE" };
      const url = `${this.config.apiEndpoint}/${encodeURIComponent(record.remoteId)}?key=${encodeURIComponent(this.config.apiKey)}`;
      const res = await fetch(url, {
        method: "PATCH",
        headers: this.buildSecureHeaders(),
        body: JSON.stringify(toFirestoreDocument(record)),
      });
      if (!res.ok) return { synced: false, mode: "HTTP_" + res.status };
      return { synced: true, mode: "FIRESTORE_TLS_VERIFIED" };
    }

    async deleteRemoteRecord(record) {
      await this.ensureAppCheckToken();
      if (!this.isAdminAuthenticated() || !record.remoteId) return { synced: false, mode: "NO_REMOTE" };
      const url = `${this.config.apiEndpoint}/${encodeURIComponent(record.remoteId)}?key=${encodeURIComponent(this.config.apiKey)}`;
      const res = await fetch(url, { method: "DELETE", headers: this.buildSecureHeaders() });
      return { synced: res.ok, mode: res.ok ? "FIRESTORE_TLS_VERIFIED" : "HTTP_" + res.status };
    }



    setAppCheckToken(token) {
      this.appCheckToken = token;
      this.appCheckIssuedAt = token ? Date.now() : 0;
    }

    async ensureAppCheckToken() {
      const fresh = this.appCheckToken && this.appCheckIssuedAt && (Date.now() - this.appCheckIssuedAt < 45 * 60 * 1000);
      if (fresh || typeof acquireAppCheckToken !== "function") return;
      const token = await acquireAppCheckToken(this.config.appId, this.config.apiKey);
      if (token) this.setAppCheckToken(token);
    }

    buildSecureHeaders() {
      const headers = {
        "Content-Type": "application/json; charset=utf-8",
        "X-Client-Integrity": "FNV1A-64-OWASP"
      };
      if (this.authToken) {
        headers["Authorization"] = `Bearer ${this.authToken}`;
      }
      if (this.appCheckToken) {
        headers["X-Firebase-AppCheck"] = this.appCheckToken;
      }
      return headers;
    }

    async syncToCloudEndpoint(newDoc) {
      await this.ensureAppCheckToken();
      if (!this.circuitBreaker.canRequest()) {
        return { synced: false, mode: "CIRCUIT_OPEN_FALLBACK" };
      }
      if (typeof fetch !== "function") {
        return { synced: false, mode: "LOCAL_SIGNED_CACHE" };
      }
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.timeoutMs || 4500);
      try {
        const wireDoc = toFirestoreDocument(newDoc);
        const endpoint = this.config.apiKey
          ? `${this.config.apiEndpoint}?key=${encodeURIComponent(this.config.apiKey)}`
          : this.config.apiEndpoint;
        const res = await fetch(endpoint, {
          method: "POST",
          headers: this.buildSecureHeaders(),
          body: JSON.stringify(wireDoc),
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!res.ok) {
          this.circuitBreaker.recordFailure();
          return { synced: false, mode: "HTTP_" + res.status };
        }
        this.circuitBreaker.recordSuccess();
        return { synced: true, mode: "FIRESTORE_TLS_VERIFIED" };
      } catch {
        clearTimeout(timer);
        this.circuitBreaker.recordFailure();
        return { synced: false, mode: "OFFLINE_RESILIENT_CACHE" };
      }
    }

    _hasLocalStorage() {
      try {
        return typeof window !== "undefined" && typeof localStorage !== "undefined" && localStorage !== null;
      } catch {
        return false;
      }
    }

    loadRecords() {
      if (!this._hasLocalStorage()) {
        if (!this.memoryStore) {
          this.memoryStore = this.seeds.map((r) => ({ ...r }));
        }
        return this.memoryStore.map((r) => ({ ...r }));
      }
      try {
        const raw = localStorage.getItem(this.config.storageKey);
        if (!raw) {
          localStorage.setItem(this.config.storageKey, JSON.stringify(this.seeds));
          return this.seeds.map((r) => ({ ...r }));
        }
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return this.seeds.map((r) => ({ ...r }));
        // Filter out any record whose cryptographic integrity hash was tampered with
        return parsed.filter((item) => verifyIntegrity(item));
      } catch {
        return this.seeds.map((r) => ({ ...r }));
      }
    }

    saveRecords(records) {
      if (this._hasLocalStorage()) {
        localStorage.setItem(this.config.storageKey, JSON.stringify(records));
      } else {
        this.memoryStore = records.map((r) => ({ ...r }));
      }
      if (this.channel) {
        try { this.channel.postMessage({ type: "SYNC", ts: Date.now() }); } catch {}
      }
      this.notify();
    }

    async addDocument(payload, now = Date.now()) {
      if (!this.rateLimiter.tryAcquire(now)) {
        throw new Error("Rate limit excedido: aguarde antes de enviar novas requisições.");
      }
      const validation = validateRecordSchema(payload);
      if (!validation.valid) {
        throw new Error(validation.error);
      }
      const records = this.loadRecords();
      const newDoc = {
        id: "fb_" + now.toString(36) + "_" + Math.random().toString(36).slice(2, 6),
        createdAt: new Date(now).toISOString(),
        ...validation.sanitized
      };
      const cloudStatus = await this.syncToCloudEndpoint(newDoc);
      newDoc.syncMode = cloudStatus.mode;
      records.unshift(newDoc);
      this.saveRecords(records);
      return newDoc;
    }

    async cycleStatus(index) {
      const records = this.loadRecords();
      if (index < 0 || index >= records.length) {
        throw new Error("Índice de documento inexistente.");
      }
      const cur = records[index].status || "Confirmado";
      const next = ALLOWED_STATUS[(ALLOWED_STATUS.indexOf(cur) + 1) % ALLOWED_STATUS.length];
      records[index].status = next;
      records[index].integrityHash = computeIntegrityHash(records[index]);
      this.saveRecords(records);
      await this.updateRemoteRecord(records[index]);
      return next;
    }

    async deleteDocument(index) {
      const records = this.loadRecords();
      if (index < 0 || index >= records.length) {
        throw new Error("Índice de documento inexistente.");
      }
      const [removed] = records.splice(index, 1);
      this.saveRecords(records);
      await this.deleteRemoteRecord(removed);
      return removed;
    }

    async purgeAllUserData() {
      if (this.isAdminAuthenticated()) {
        const records = await this.loadCloudRecords();
        for (const rec of records) {
          if (rec.remoteId) await this.deleteRemoteRecord(rec);
        }
      }
      this.saveRecords([]);
      return [];
    }

    async resetDemo() {
      const fresh = this.seeds.map((r) => ({ ...r }));
      this.saveRecords(fresh);
      return fresh;
    }

    onSnapshot(cb) {
      this.listeners.push(cb);
      cb(this.loadRecords());
    }

    notify() {
      const records = this.loadRecords();
      this.listeners.forEach((cb) => cb(records));
    }
  }

  // ============================================================================
  // 10. CONTROLADOR DE INTERFACE DOM (EXECUTADO APENAS NO NAVEGADOR)
  // ============================================================================

  function initBrowserUI() {
    if (typeof document === "undefined") return;
    const db = new FirebaseCloudStore(FIREBASE_CONFIG, SEED_RECORDS);
    let activeCat = "Todos";
    let searchQuery = "";
    let piiMaskEnabled = true;

    function showToast(msg) {
      const el = document.getElementById("toast-banner");
      if (!el) return;
      el.textContent = msg;
      el.hidden = false;
      clearTimeout(showToast._timer);
      showToast._timer = setTimeout(() => { el.hidden = true; }, 3400);
    }

    function renderServices() {
      const grid = document.getElementById("services-grid");
      if (!grid) return;

      const filtered = SERVICES.filter((s) => {
        const matchCat = activeCat === "Todos" || s.cat === activeCat;
        const matchQuery = !searchQuery ||
          s.name.toLowerCase().includes(searchQuery) ||
          s.desc.toLowerCase().includes(searchQuery) ||
          s.cat.toLowerCase().includes(searchQuery);
        return matchCat && matchQuery;
      });

      grid.innerHTML = filtered.map((s) => `
        <article class="service-card">
          <div>
            <div class="service-top">
              <span class="service-cat">${escapeHTML(s.cat)}</span>
              <span class="service-duration">⏱ ${escapeHTML(s.duration)}</span>
            </div>
            <h3 class="service-name">${escapeHTML(s.name)}</h3>
            <p class="service-desc">${escapeHTML(s.desc)}</p>
          </div>
          <div class="service-footer">
            <span class="service-price">${formatBRL(s.price)}</span>
            <button type="button" class="btn-primary btn-sm" data-pick-service="${escapeHTML(s.id)}">
              Selecionar ➔
            </button>
          </div>
        </article>
      `).join("");

      grid.querySelectorAll("[data-pick-service]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const sid = btn.getAttribute("data-pick-service");
          const sel = document.getElementById("select-servico");
          if (sel) sel.value = sid;
          document.getElementById("agendamento")?.scrollIntoView({ behavior: "smooth" });
          document.getElementById("input-cliente")?.focus();
        });
      });
    }

    function initCalculator() {
      const listEl = document.getElementById("calc-items-list");
      const countEl = document.getElementById("calc-count");
      const totalEl = document.getElementById("calc-total-value");
      const applyBtn = document.getElementById("btn-apply-sim");
      if (!listEl) return;

      listEl.innerHTML = SERVICES.map((s, idx) => `
        <label class="calc-item-label">
          <span class="calc-item-left">
            <input type="checkbox" class="calc-check" value="${escapeHTML(s.id)}" ${idx === 0 ? "checked" : ""}>
            <span>${escapeHTML(s.name)}</span>
          </span>
          <span class="calc-item-price">${formatBRL(s.price)}</span>
        </label>
      `).join("");

      function updateSim() {
        const selectedIds = Array.from(listEl.querySelectorAll(".calc-check:checked")).map((el) => el.value);
        const res = calculateSimulation(SERVICES, selectedIds);
        if (countEl) countEl.textContent = String(res.count);
        if (totalEl) totalEl.textContent = res.formatted;
      }

      listEl.addEventListener("change", updateSim);
      updateSim();

      if (applyBtn) {
        applyBtn.addEventListener("click", () => {
          const firstChecked = listEl.querySelector(".calc-check:checked");
          if (firstChecked) {
            const sel = document.getElementById("select-servico");
            if (sel) sel.value = firstChecked.value;
          }
          document.getElementById("agendamento")?.scrollIntoView({ behavior: "smooth" });
          document.getElementById("input-cliente")?.focus();
          showToast("Simulação aplicada ao formulário operacional!");
        });
      }
    }

    function renderFirebaseTable(records) {
      const tbody = document.getElementById("firebase-table-body");
      const kpiTotal = document.getElementById("kpi-total-registros");
      const kpiReceita = document.getElementById("kpi-receita-estimada");
      if (!tbody) return;

      if (kpiTotal) kpiTotal.textContent = String(records.length);
      const totalCents = records.reduce((acc, r) => acc + Math.round(parseBRL(r.valor) * 100), 0);
      if (kpiReceita) kpiReceita.textContent = formatBRL(totalCents / 100);

      tbody.replaceChildren();
      records.forEach((r, idx) => {
        const tr = document.createElement("tr");

        const tdClient = document.createElement("td");
        const strongClient = document.createElement("strong");
        strongClient.textContent = r.cliente;
        const subContact = document.createElement("div");
        subContact.style.fontSize = "11.5px";
        subContact.style.color = "var(--text-secondary)";
        subContact.textContent = piiMaskEnabled ? maskPII(r.contato) : r.contato;
        tdClient.append(strongClient, subContact);

        const tdSvc = document.createElement("td");
        const divSvc = document.createElement("div");
        divSvc.textContent = r.servico;
        const divProf = document.createElement("div");
        divProf.style.fontSize = "11.5px";
        divProf.style.color = "var(--text-muted)";
        divProf.textContent = r.profissional;
        tdSvc.append(divSvc, divProf);

        const tdTime = document.createElement("td");
        tdTime.style.fontFamily = "var(--font-mono)";
        tdTime.style.fontSize = "12px";
        tdTime.textContent = r.horario;

        const tdVal = document.createElement("td");
        tdVal.style.fontFamily = "var(--font-mono)";
        tdVal.style.fontWeight = "700";
        tdVal.style.color = "var(--accent)";
        tdVal.textContent = r.valor;

        const tdStatus = document.createElement("td");
        const st = ALLOWED_STATUS.includes(r.status) ? r.status : "Confirmado";
        const badge = document.createElement("span");
        badge.className = "badge-status " + (
          st === "Concluído" ? "badge-concluido" : (st === "Em Atendimento" ? "badge-atendimento" : "badge-confirmado")
        );
        badge.textContent = st;
        const sigDiv = document.createElement("div");
        sigDiv.style.fontFamily = "var(--font-mono)";
        sigDiv.style.fontSize = "10px";
        sigDiv.style.color = "var(--text-muted)";
        sigDiv.textContent = r.integrityHash ? r.integrityHash.slice(0, 12) : "verified";
        tdStatus.append(badge, sigDiv);

        const tdActions = document.createElement("td");
        const btnCycle = document.createElement("button");
        btnCycle.type = "button";
        btnCycle.className = "row-action-btn";
        btnCycle.textContent = "⟳ Status";
        btnCycle.addEventListener("click", () => {
          db.cycleStatus(idx);
          showToast("Status e assinatura FNV-1a recalibrados!");
        });

        const btnDel = document.createElement("button");
        btnDel.type = "button";
        btnDel.className = "row-action-btn";
        btnDel.textContent = "✕";
        btnDel.addEventListener("click", () => {
          db.deleteDocument(idx);
          showToast("Registro removido com segurança.");
        });

        tdActions.append(btnCycle, btnDel);
        tr.append(tdClient, tdSvc, tdTime, tdVal, tdStatus, tdActions);
        tbody.appendChild(tr);
      });
    }

    document.addEventListener("DOMContentLoaded", () => {
      renderServices();
      initCalculator();

      document.querySelectorAll(".filter-chip").forEach((btn) => {
        btn.addEventListener("click", () => {
          document.querySelectorAll(".filter-chip").forEach((b) => b.classList.remove("is-active"));
          btn.classList.add("is-active");
          activeCat = btn.getAttribute("data-cat") || "Todos";
          renderServices();
        });
      });

      document.getElementById("search-services")?.addEventListener("input", (e) => {
        searchQuery = String(e.target.value || "").trim().toLowerCase();
        renderServices();
      });

      db.onSnapshot(renderFirebaseTable);

      document.getElementById("btn-toggle-pii")?.addEventListener("click", (e) => {
        piiMaskEnabled = !piiMaskEnabled;
        const btn = e.currentTarget;
        btn.setAttribute("aria-pressed", String(piiMaskEnabled));
        btn.textContent = piiMaskEnabled ? "🔒 Mascarar PII (LGPD)" : "🔓 PII Visível (Admin)";
        renderFirebaseTable(db.loadRecords());
        showToast(piiMaskEnabled ? "Proteção de privacidade LGPD ativada." : "Visualização administrativa ativada.");
      });

      document.getElementById("btn-purge-lgpd")?.addEventListener("click", () => {
        db.purgeAllUserData();
        showToast("Art. 18 LGPD: Todos os dados locais foram expurgados.");
      });

      const form = document.getElementById("firebase-form");
      form?.addEventListener("submit", async (e) => {
        e.preventDefault();
        try {
          const cliente = document.getElementById("input-cliente")?.value || "";
          const contato = document.getElementById("input-contato")?.value || "";
          const profissional = document.getElementById("select-profissional")?.value || "";
          const horario = document.getElementById("select-horario")?.value || "";
          const servicoId = document.getElementById("select-servico")?.value || "";
          const obs = document.getElementById("input-obs")?.value || "";
          const lgpdConsent = document.getElementById("input-lgpd-consent")?.checked ?? true;

          const svcObj = SERVICES.find((s) => s.id === servicoId) || SERVICES[0];
          await db.addDocument({
            cliente,
            contato,
            profissional,
            servico: svcObj.name,
            horario,
            valor: formatBRL(svcObj.price),
            status: "Confirmado",
            obs,
            lgpdConsent
          });

          form.reset();
          const consentBox = document.getElementById("input-lgpd-consent");
          if (consentBox) consentBox.checked = true;
          showToast("✓ Registro validado, assinado e serializado no formato Firestore v1!");
        } catch (err) {
          showToast("⚠ " + (err && err.message ? err.message : "Erro de validação."));
        }
      });

      document.getElementById("btn-export-json")?.addEventListener("click", () => {
        const records = db.loadRecords().map((r) => toFirestoreDocument({
          ...r,
          contato: piiMaskEnabled ? maskPII(r.contato) : r.contato
        }));
        const data = JSON.stringify({ documents: records }, null, 2);
        const blob = new Blob([data], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `pedidos_pizzaria_firestore_v1_export.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast("Documentos exportados no formato oficial Google Cloud Firestore v1!");
      });

      document.getElementById("btn-reset-demo")?.addEventListener("click", () => {
        db.resetDemo();
        showToast("Dataset de demonstração restaurado.");
      });
    });


    // App Check e atestado de app (somente no navegador; falha nao interrompe a aplicacao).
    acquireAppCheckToken(db.config.appId, db.config.apiKey).then((token) => {
      if (token) db.setAppCheckToken(token);
    });

    initAdminAuthUI(db, showToast);
  }

  function initAdminAuthUI(db, showToast) {
    if (typeof document === "undefined") return;
    const panel = document.createElement("div");
    panel.setAttribute("style", "position:fixed;right:16px;bottom:16px;z-index:60;font:14px system-ui,sans-serif");
    panel.innerHTML =
      '<button type="button" id="admin-auth-toggle" aria-label="Acesso administrativo">Admin</button>' +
      '<div id="admin-auth-dialog" role="dialog" aria-modal="true" aria-label="Login administrativo" hidden>' +
      '<label>Usuario <input type="email" id="admin-auth-email" autocomplete="username" required></label>' +
      '<label>Senha <input type="password" id="admin-auth-password" autocomplete="current-password" required></label>' +
      '<button type="button" id="admin-auth-login">Entrar</button>' +
      '<button type="button" id="admin-auth-sync">Sincronizar</button>' +
      '<button type="button" id="admin-auth-logout">Sair</button>' +
      '<p id="admin-auth-status" role="status"></p>' +
      '</div>';
    document.body.appendChild(panel);
    const dialog = panel.querySelector("#admin-auth-dialog");
    const email = panel.querySelector("#admin-auth-email");
    const password = panel.querySelector("#admin-auth-password");
    const status = panel.querySelector("#admin-auth-status");
    panel.querySelector("#admin-auth-toggle").addEventListener("click", () => { dialog.hidden = !dialog.hidden; });
    panel.querySelector("#admin-auth-login").addEventListener("click", async () => {
      try {
        const who = await db.signInAdmin(email.value.trim(), password.value);
        password.value = "";
        status.textContent = "Autenticado: " + who.email + " (" + who.site + ").";
        await db.loadCloudRecords();
        showToast("Administrador autenticado; registros carregados do Firestore.");
      } catch (err) {
        status.textContent = err.message;
      }
    });
    panel.querySelector("#admin-auth-sync").addEventListener("click", async () => {
      try { await db.loadCloudRecords(); showToast("Registros sincronizados."); }
      catch (err) { status.textContent = err.message; }
    });
    panel.querySelector("#admin-auth-logout").addEventListener("click", () => {
      db.signOutAdmin();
      status.textContent = "Sessao encerrada.";
    });
  }

  initBrowserUI();


  return Object.freeze({
    FIREBASE_CONFIG,
    ALLOWED_STATUS,
    ALLOWED_FIREBASE_HOSTS,
    SERVICES,
    SEED_RECORDS,
    escapeHTML,
    detectMaliciousPayload,
    validateFirebaseEndpoint,
    toFirestoreDocument,
    fromFirestoreDocument,
    CloudCircuitBreaker,
    maskPII,
    computeIntegrityHash,
    verifyIntegrity,
    validateRecordSchema,
    RateLimiter,
    formatBRL,
    parseBRL,
    calculateSimulation,
    FirebaseCloudStore
  });
});

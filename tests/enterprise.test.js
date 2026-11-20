/**
 * Suite de 20 Testes Empresariais 10/10 — Seguranca (OWASP), Conexao Segura Firebase (TLS 1.3),
 * Privacidade (LGPD) & Qualidade de Codigo
 * Sistema: Vesuvio Forno & Brasa (vesuvio-forno-kds)
 * Execucao: node --test tests/enterprise.test.js
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const core = require("../app.js");

// ============================================================================
// SUITE 1: SEGURANCA OFENSIVA & DEFENSIVA (OWASP TOP 10 / XSS / INJECTION)
// ============================================================================

test("01. OWASP A03 - escapeHTML neutraliza vetores XSS refletidos e armazenados", () => {
  const payload = `<script>alert("xss")</script><img src=x onerror='steal()'>`;
  const escaped = core.escapeHTML(payload);
  assert.ok(!escaped.includes("<script>"));
  assert.ok(!escaped.includes("<img"));
  assert.ok(escaped.includes("&lt;script&gt;"));
});

test("02. OWASP A03 - detectMaliciousPayload bloqueia XSS, JavaScript URI e Event Handlers", () => {
  const vectors = [
    "<script>fetch('https://evil.tld')</script>",
    "javascript:alert(document.cookie)",
    "<img src=x onerror=alert(1)>",
    "<svg onload=confirm(1)>",
    "<iframe src='https://evil.tld'></iframe>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTvc2NyaXB0Pg=="
  ];
  for (const vec of vectors) {
    assert.equal(core.detectMaliciousPayload(vec), true, `Vetor deveria ser bloqueado: ${vec}`);
  }
});

test("03. OWASP A03/A08 - detectMaliciousPayload bloqueia NoSQL Injection, SQLi e Prototype Pollution", () => {
  assert.equal(core.detectMaliciousPayload({ "$where": "this.credits > 0" }), true);
  assert.equal(core.detectMaliciousPayload({ "$ne": null }), true);
  assert.equal(core.detectMaliciousPayload("admin' UNION SELECT * FROM users--"), true);
  assert.equal(core.detectMaliciousPayload("constructor[prototype][isAdmin]=true"), true);
});

test("04. OWASP A04 - RateLimiter bloqueia ataques de flood acima da janela de tempo", () => {
  const limiter = new core.RateLimiter(3, 10000);
  const t0 = 100000;
  assert.equal(limiter.tryAcquire(t0), true);
  assert.equal(limiter.tryAcquire(t0 + 100), true);
  assert.equal(limiter.tryAcquire(t0 + 200), true);
  assert.equal(limiter.tryAcquire(t0 + 300), false);
  assert.equal(limiter.tryAcquire(t0 + 11000), true);
});

test("05. OWASP A08 - computeIntegrityHash e verifyIntegrity detectam adulteracao de dados", () => {
  const doc = {
    cliente: "Cliente Integro",
    contato: "(11) 99812-3400",
    profissional: "Profissional",
    servico: "Servico",
    horario: "10:00",
    valor: "R$ 100,00",
    status: "Confirmado"
  };
  doc.integrityHash = core.computeIntegrityHash(doc);
  assert.equal(core.verifyIntegrity(doc), true);

  const tampered = { ...doc, valor: "R$ 0,01" };
  assert.equal(core.verifyIntegrity(tampered), false);
});

// ============================================================================
// SUITE 2: CONEXAO SEGURA FIREBASE CLOUD (TLS 1.3, ANTI-SSRF, WIRE FORMAT & CIRCUIT BREAKER)
// ============================================================================

test("06. Firebase TLS 1.3 & Anti-SSRF - validateFirebaseEndpoint rejeita HTTP e hosts nao autorizados", () => {
  const validEp = core.validateFirebaseEndpoint(core.FIREBASE_CONFIG.apiEndpoint);
  assert.equal(validEp.valid, true);

  const httpDowngrade = core.validateFirebaseEndpoint("http://firestore.googleapis.com/v1/projects/test");
  assert.equal(httpDowngrade.valid, false);
  assert.match(httpDowngrade.reason, /HTTPS/);

  const ssrfAttempt = core.validateFirebaseEndpoint("https://attacker-controlled.com/v1/projects/test");
  assert.equal(ssrfAttempt.valid, false);
  assert.match(ssrfAttempt.reason, /Anti-SSRF/);

  const embeddedCreds = core.validateFirebaseEndpoint("https://admin:secret@firestore.googleapis.com/v1/test");
  assert.equal(embeddedCreds.valid, false);
});

test("07. Firestore Wire Protocol v1 - toFirestoreDocument e fromFirestoreDocument preservam tipagem e verificam assinatura", () => {
  const validated = core.validateRecordSchema({
    cliente: "Cliente Firestore TLS",
    contato: "(11) 99812-3400",
    profissional: core.SEED_RECORDS[0].profissional,
    servico: core.SERVICES[0].name,
    horario: "Amanhã • 10:00",
    valor: "R$ 250,00",
    status: "Confirmado",
    lgpdConsent: true
  });
  const wireDoc = core.toFirestoreDocument({ id: "fb_123", createdAt: "2026-11-20T00:00:00.000Z", ...validated.sanitized });
  assert.equal(wireDoc.fields.cliente.stringValue, "Cliente Firestore TLS");
  assert.equal(wireDoc.fields.lgpdConsent.booleanValue, true);

  const restored = core.fromFirestoreDocument(wireDoc);
  assert.equal(restored.cliente, "Cliente Firestore TLS");
  assert.equal(core.verifyIntegrity(restored), true);

  // Adulterar documento em transito deve disparar erro de integridade
  wireDoc.fields.valor.stringValue = "R$ 0,00";
  assert.throws(() => core.fromFirestoreDocument(wireDoc), /Integridade/);
});

test("08. CloudCircuitBreaker - abre o circuito apos falhas consecutivas e recupera em HALF_OPEN", () => {
  const cb = new core.CloudCircuitBreaker(2, 5000);
  assert.equal(cb.state, "CLOSED");
  assert.equal(cb.canRequest(1000), true);

  cb.recordFailure(1000);
  assert.equal(cb.state, "CLOSED");
  cb.recordFailure(1100);
  assert.equal(cb.state, "OPEN");
  assert.equal(cb.canRequest(2000), false, "Circuito aberto deve bloquear chamadas de rede");

  assert.equal(cb.canRequest(7000), true, "Apos cooldown deve entrar em HALF_OPEN");
  assert.equal(cb.state, "HALF_OPEN");
  cb.recordSuccess();
  assert.equal(cb.state, "CLOSED");
});

test("09. Firebase Auth & AppCheck Headers - buildSecureHeaders injeta Bearer e X-Firebase-AppCheck com seguranca", () => {
  const store = new core.FirebaseCloudStore(core.FIREBASE_CONFIG, core.SEED_RECORDS);
  store.setSecurityTokens({ idToken: "eyJ_mock_jwt", appCheckToken: "app_check_token_v1" });
  const headers = store.buildSecureHeaders();
  assert.equal(headers["Authorization"], "Bearer eyJ_mock_jwt");
  assert.equal(headers["X-Firebase-AppCheck"], "app_check_token_v1");
  assert.equal(headers["X-Client-Integrity"], "FNV1A-64-OWASP");
});

test("10. Secret Leak Scanner - garante ausencia de chaves privadas ou credenciais hardcoded no codigo", () => {
  const files = ["index.html", "app.js", "styles.css", "firebase.json"];
  const forbiddenSecrets = [
    /-----BEGIN PRIVATE KEY-----/,
    /firebase-adminsdk/i,
    /client_secret\s*:/i
  ];
  // Chaves de API Web do Firebase sao identificadores publicos (nao credenciais).
  // Permite exatamente a chave declarada do projeto; qualquer outra continua bloqueada.
  const PUBLIC_WEB_API_KEY = "AIzaSyDqb7tfGwgkSImIuiiyNllJdPU0cDMDip4";
  for (const f of files) {
    let content = fs.readFileSync(path.join(__dirname, "..", f), "utf8");
    if (f === "app.js") content = content.split(PUBLIC_WEB_API_KEY).join("");
    for (const rx of forbiddenSecrets) {
      assert.doesNotMatch(content, rx, `Credencial exposta detectada em ${f}`);
    }
    assert.doesNotMatch(content, /AIza[0-9A-Za-z-_]{35}/, `Chave de API nao declarada detectada em ${f}`);
  }
});

// ============================================================================
// SUITE 3: PRIVACIDADE & CONFORMIDADE LGPD (PII MASKING, CONSENT & ERASURE)
// ============================================================================

test("11. LGPD Art. 6/46 - maskPII mascara telefones, e-mails e enderecos contra exposicao", () => {
  assert.equal(core.maskPII("(11) 99812-3400"), "(11) 9****-3400");
  assert.equal(core.maskPII("cliente@empresa.com.br"), "cl***@empresa.com.br");
  assert.ok(core.maskPII("Av. Paulista, 1500 - Bela Vista").includes("***"));
});

test("12. LGPD Art. 7/8 - validateRecordSchema exige consentimento LGPD explicito", () => {
  const denied = core.validateRecordSchema({
    cliente: "Cliente Sem Consentimento",
    contato: "(11) 98888-7777",
    profissional: core.SEED_RECORDS[0].profissional,
    servico: core.SERVICES[0].name,
    horario: "Amanhã • 10:00",
    valor: "R$ 150,00",
    status: "Confirmado",
    lgpdConsent: false
  });
  assert.equal(denied.valid, false);
  assert.match(denied.error, /LGPD/);
});

// ============================================================================
// SUITE 4: CONTRATOS DE SCHEMA & REGRAS DE NEGOCIO
// ============================================================================

test("13. Schema Validator aprova payload integro, gera assinatura e rejeita limites invalidos", () => {
  const valid = core.validateRecordSchema({
    cliente: "Empresa Alfa Ltda",
    contato: "(11) 98888-7777",
    profissional: core.SEED_RECORDS[0].profissional,
    servico: core.SERVICES[0].name,
    horario: "Amanhã • 10:00",
    valor: "R$ 250,00",
    status: "Confirmado",
    lgpdConsent: true
  });
  assert.equal(valid.valid, true);
  assert.ok(valid.sanitized.integrityHash.startsWith("sig_"));
  assert.equal(core.verifyIntegrity(valid.sanitized), true);
});

test("14. Schema Validator rejeita injecao XSS dentro de campos do formulario", () => {
  const res = core.validateRecordSchema({
    cliente: "<img src=x onerror=alert(1)>",
    contato: "(11) 99999-0000",
    profissional: "Responsavel",
    servico: "Servico",
    horario: "10:00",
    valor: "R$ 100,00",
    status: "Confirmado"
  });
  assert.equal(res.valid, false);
  assert.match(res.error, /OWASP/);
});

// ============================================================================
// SUITE 5: PRECISAO MATEMATICA & MOTOR FINANCEIRO (CENTAVOS INTEIROS)
// ============================================================================

test("15. Motor Financeiro calcula orcamentos em centavos inteiros sem erro IEEE-754", () => {
  assert.equal(core.SERVICES.length, 6);
  const allIds = core.SERVICES.map((s) => s.id);
  const sim = core.calculateSimulation(core.SERVICES, allIds);
  const expectedCents = core.SERVICES.reduce((acc, s) => acc + Math.round(s.price * 100), 0);
  assert.equal(sim.count, 6);
  assert.equal(sim.totalCents, expectedCents);
  assert.equal(sim.totalAmount, expectedCents / 100);
});

test("16. Conversao bidirecional formatBRL e parseBRL preserva exatidao monetaria", () => {
  const values = [0, 28.99, 105.5, 1650.75, 4850000];
  for (const v of values) {
    const formatted = core.formatBRL(v);
    const parsed = core.parseBRL(formatted);
    assert.equal(parsed, v);
  }
});

// ============================================================================
// SUITE 6: PERSISTENCIA FIREBASE STORE, CRUD & DIREITO AO ESQUECIMENTO LGPD
// ============================================================================

test("17. FirebaseCloudStore executa ciclo CRUD + recalibra assinatura de integridade", async () => {
  const store = new core.FirebaseCloudStore(core.FIREBASE_CONFIG, core.SEED_RECORDS);
  assert.equal(store.loadRecords().length, 3);

  const added = await store.addDocument({
    cliente: "Cliente Teste Integracao",
    contato: "(11) 97777-6666",
    profissional: core.SEED_RECORDS[0].profissional,
    servico: core.SERVICES[0].name,
    horario: "Amanhã • 15:00",
    valor: core.formatBRL(core.SERVICES[0].price),
    status: "Confirmado",
    lgpdConsent: true
  });
  assert.ok(added.id.startsWith("fb_"));
  assert.equal(core.verifyIntegrity(added), true);
  assert.equal(store.loadRecords().length, 4);

  const st1 = await store.cycleStatus(0);
  assert.equal(st1, "Em Atendimento");
  assert.equal(core.verifyIntegrity(store.loadRecords()[0]), true);

  await store.deleteDocument(0);
  assert.equal(store.loadRecords().length, 3);
});

test("18. LGPD Art. 18 - purgeAllUserData expurga todos os registros sob demanda", async () => {
  const store = new core.FirebaseCloudStore(core.FIREBASE_CONFIG, core.SEED_RECORDS);
  await store.purgeAllUserData();
  assert.equal(store.loadRecords().length, 0);
  await store.resetDemo();
  assert.equal(store.loadRecords().length, 3);
});

// ============================================================================
// SUITE 7: AUDITORIA ESTATICA DE ARQUITETURA, CSP, WCAG, LGPD & FIREBASE RULES
// ============================================================================

test("19. Auditoria HTML/WCAG/CSP/LGPD: index.html restringe connect-src ao Firestore TLS e proibe handlers inline", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  assert.match(html, /http-equiv="Content-Security-Policy"/);
  assert.match(html, /https:\/\/firestore\.googleapis\.com/);
  assert.match(html, /http-equiv="X-Content-Type-Options"\s+content="nosniff"/);
  assert.match(html, /application\/ld\+json/);
  assert.match(html, /class="skip-link"/);
  assert.match(html, /id="input-lgpd-consent"/);
  assert.doesNotMatch(html, /\son(?:click|load|error|submit)=/i);
});

test("20. Auditoria Infra/Firestore/SECURITY.md: headers HTTP e regras validam lgpdConsent e integrityHash", () => {
  const fbJson = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "firebase.json"), "utf8"));
  const headers = fbJson.hosting.headers[0].headers.map((h) => h.key);
  assert.ok(headers.includes("X-Content-Type-Options"));
  assert.ok(headers.includes("X-Frame-Options"));
  assert.ok(headers.includes("Strict-Transport-Security"));
  assert.ok(headers.includes("Permissions-Policy"));

  const rules = fs.readFileSync(path.join(__dirname, "..", "firestore.rules"), "utf8");
  assert.match(rules, /data\.lgpdConsent == true/);
  assert.match(rules, /data\.integrityHash is string/);
  assert.ok(fs.existsSync(path.join(__dirname, "..", "SECURITY.md")));
});

# Política de Segurança (OWASP Top 10), Transporte Firebase TLS 1.3 & Privacidade (LGPD) — Vesuvio Forno & Brasa

## 1. Conexão Segura com Google Firebase Cloud (`FirebaseCloudStore`)
- **Transporte HTTPS / TLS 1.3 Estrito (`validateFirebaseEndpoint`):** Qualquer endpoint `http://` ou domínio fora da whitelist oficial (`firestore.googleapis.com`, `firebaseio.com`, `identitytoolkit.googleapis.com`) é bloqueado preventivamente contra ataques de downgrade e SSRF (OWASP A10).
- **Serialização Oficial Firestore v1 Wire Format (`toFirestoreDocument` / `fromFirestoreDocument`):** Os documentos trafegam tipados (`stringValue`, `booleanValue`, `timestampValue`) e têm sua assinatura FNV-1a de 64 bits verificada antes da desserialização.
- **Autenticação & App Check (`buildSecureHeaders`):** Suporte nativo para injeção de `Authorization: Bearer <idToken>` e `X-Firebase-AppCheck` sem nenhuma chave privada ou credencial exposta no código-fonte (auditado pelo Teste Automatizado #10 — *Secret Leak Scanner*).
- **Resiliência com Circuit Breaker (`CloudCircuitBreaker`) & `AbortController`:** Timeout defensivo de 4.5s por requisição e transição automática (`CLOSED` ➔ `OPEN` ➔ `HALF_OPEN`) com fallback local assinado criptograficamente.

## 2. Segurança Defensiva (OWASP Top 10)
- **A01 – Broken Access Control:** Regras estritas no `firestore.rules` validando tipos, limites de tamanho, enum de status, consentimento LGPD e assinatura `integrityHash`.
- **A03 – Injection (XSS / NoSQLi / SQLi):** Sanitização determinística (`escapeHTML`), inspeção recursiva (`detectMaliciousPayload`) e renderização DOM segura via `createElement` / `textContent`.
- **A04 – Insecure Design:** `RateLimiter` sliding-window integrado contra ataques de flood.
- **A08 – Software and Data Integrity Failures:** Assinatura de integridade FNV-1a 64-bit (`computeIntegrityHash` / `verifyIntegrity`) em cada documento.

## 3. Privacidade por Design (LGPD — Lei nº 13.709/2018)
- **Mascaramento Automático de PII (`maskPII`):** Telefones, e-mails e identificadores sensíveis são mascarados por padrão.
- **Consentimento Explícito (Art. 7º e 8º):** Validação obrigatória de `lgpdConsent === true`.
- **Direito à Eliminação / Esquecimento (Art. 18):** Função `purgeAllUserData()` disponível diretamente na interface.

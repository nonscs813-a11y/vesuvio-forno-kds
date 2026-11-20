# Politica de Seguranca, Tenant Isolation & LGPD — Vesuvio Forno Kds

## 1. Arquitetura de confianca (producao, plano Spark / sem custo)
- **Firebase Auth (email/senha)** habilitado no projeto `julio-enterprise-suite`; 10 contas de administrador, uma por site, com **custom claims** `{ site, role: site_admin }`.
- **Isolamento de tenant real no Firestore**: `firestore.rules` exige `request.auth.token.site == '<site>'` e `role == 'site_admin'` para `get/list/update/delete`. Nenhum `allow read: if true` resta.
- **Criacao publica controlada**: visitantes podem criar agendamentos, mas apenas com `lgpdConsent == true`, schema validado e `integrityHash` de 20 caracteres. Leitura de PII e alteracoes exigem login.
- **Transporte**: HTTPS/TLS restrito a hosts oficiais (`validateFirebaseEndpoint`), anti-SSRF e circuit breaker com timeout de 4,5s.
- **Chave Web publica**: identificador de app, restrita a APIs Firebase. Autorizacao verdadeira vem das regras + token do Firebase Auth (`Authorization: Bearer`).

## 2. OWASP Top 10
- **A01 Broken Access Control**: regras por tenant + claims; verificado por 32 assertions de integracao (leitura cruzada entre os 10 sites negada).
- **A03 Injection**: `escapeHTML`, `detectMaliciousPayload`, renderizacao via `textContent`.
- **A04 Insecure Design**: `RateLimiter` sliding-window no cliente (defesa complementar; limite autoritativo depende de App Check/gateway).
- **A08 Integrity**: FNV-1a de 64 bits por documento; detecta adulteracao, **nao** e assinatura criptografica nem autorizacao.

## 3. LGPD (Lei 13.709/2018)
- **Art. 7/8**: consentimento explicito obrigatorio no payload e na regra (`lgpdConsent == true`).
- **Art. 18**: `purgeAllUserData()` autenticado lista e **exclui os documentos remotos no Firestore** antes de limpar o cache local.
- **Mascaramento**: `maskPII` aplicado por padrao na interface.

## 4. Operacao
- Credenciais administrativas **nao** estao no codigo-fonte: o administrador informa e-mail/senha na interface; o ID token fica apenas em memoria.
- CI executa testes unitarios e estaticos sem gravar no Firestore; integracao real roda em suite separada com limpeza automatica.
- **Limites do plano Spark** (sem pagamento): sem Cloud Functions, sem Cloud Storage, sem PITR/backup gerenciado, sem SMS/Phone Auth. App Check reCAPTCHA v3 esta disponivel no tier gratuito.

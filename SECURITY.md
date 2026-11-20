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

## 5. App Check (Fraud Defense / reCAPTCHA Enterprise) - plano gratuito
- 10 apps Web registrados no App Check com o provedor recaptchaEnterpriseConfig (site key publica 6LcgySkuAAAAAEtMX3v4cK514gKQZJvsAJ4fPVb2), dominios autorizados: julio-enterprise-suite.web.app, julio-enterprise-suite.firebaseapp.com e localhost.
- O cliente gera o token reCAPTCHA, troca por um App Check token (:exchangeRecaptchaEnterpriseToken) e envia X-Firebase-AppCheck em cada requisicao ao Firestore.
- Modo atual: ENFORCED em firestore.googleapis.com — requisicoes sem token App Check sao negadas com HTTP 403 (validado na suite). A automacao local usa um debug token restrito a infraestrutura (fora dos repositorios); o navegador usa tokens reais do reCAPTCHA Enterprise. Ate 10.000 avaliacoes/mes sem custo.
- Chave Web restrita a 6 APIs (Firestore, Auth, Secure Token, App Check, Installations, Firebase) - reduz blast radius em caso de vazamento.

## 6. Estado de producao
- Controle de acesso, isolamento por tenant, criptografia em transito, consentimento e exclusao remota: implementados e validados por suite automatizada.
- App Check: configurado e verificado (emissao de token real funcionando); enforcement e o unico passo manual restante.
- Limites intrinsecos do Spark (sem custo): sem Cloud Functions, Cloud Storage, PITR/backup gerenciado, SMS/Phone Auth ou excedente de cota. Backup logico e monitoramento avancado exigem servico externo ou upgrade.

## 7. Governanca operacional (sem custo)
- Cofre local com DPAPI do Windows: credenciais dos 10 admins e o debug token do App Check ficam cifrados por usuario/maquina, nunca em texto puro (firebase-infra/secrets/).
- Exportacao logica diaria de todas as colecoes (inclusive auditoria) para blob cifrado, com retencao de 30 dias; agendada via Agendador de Tarefas do Windows.
- Trilha de auditoria em audit_logs/{site}/events: somente o admin do tenant cria; update e delete sao negados pelas regras. Eventos de login, sincronizacao, troca de status, exclusao e purga LGPD sao registrados.
- Automacao usa App Check token real (exchangeDebugToken) e nunca reenvia o segredo do debug token ao Firestore.

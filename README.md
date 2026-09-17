# API de Autenticação e Autorização

API de autenticação em Java com Spring Boot e Spring Security, com cadastro/login, emissão e validação de JWT (access + refresh token), e endpoints protegidos por papel (role).

## Status

✅ MVP implementado.

## Stack

- Java 17 + Spring Boot 3.3 (Spring Security)
- JWT via [jjwt](https://github.com/jwtk/jjwt) (HMAC-SHA512)
- PostgreSQL + Spring Data JPA + Flyway
- Lombok (nas entidades JPA)
- Gradle (Kotlin DSL) + wrapper `gradlew`
- Testcontainers (testes de integração) + Spring Security Test + JUnit 5 + Mockito

## Fluxo de autenticação

```
POST /auth/register  →  BCrypt(senha)  →  PostgreSQL (role padrão: ROLE_USER)

POST /auth/login  →  AuthenticationManager (valida email/senha)  →  JWT access + refresh

Requisição em endpoint protegido
  → Authorization: Bearer <access token>
  → JwtAuthenticationFilter valida assinatura, expiração e tipo do token
  → popula o SecurityContext com as roles do token
  → regra de autorização do endpoint decide 200 / 401 / 403

POST /auth/refresh  →  valida que é um refresh token válido  →  novo par access + refresh
```

Access token e refresh token são o mesmo tipo de JWT, assinados com a mesma chave, mas carregam um claim `type` (`access` ou `refresh`) — o filtro de autenticação só aceita tokens `access`, e `/auth/refresh` só aceita `refresh`. Isso evita que um refresh token vazado seja usado diretamente para chamar endpoints protegidos, e que um access token seja usado para gerar novos tokens indefinidamente.

## Boas práticas aplicadas

- Senha **nunca** armazenada nem logada em texto plano — sempre `BCrypt` (via `PasswordEncoder`), com o hash de custo adaptativo padrão do Spring Security.
- Mensagem de erro de login genérica ("Invalid email or password") tanto para e-mail inexistente quanto para senha errada — evita enumeração de usuários cadastrados.
- Access token de vida curta (15 min) e refresh token de vida mais longa (7 dias), configuráveis via `app.jwt.access-token-ttl` / `app.jwt.refresh-token-ttl`.
- `SessionCreationPolicy.STATELESS` — nenhuma sessão HTTP é criada; toda autenticação é reconstruída a partir do JWT em cada requisição.
- Erros de autenticação (401) e autorização (403) retornam um corpo JSON padronizado (`JwtAuthenticationEntryPoint` / `JwtAccessDeniedHandler`), consistente com o restante da API, em vez da página de erro padrão do Spring.
- O segredo do JWT em `application.yml` é **só para demonstração**; em um deploy real ele viria de uma variável de ambiente/secret manager e nunca seria versionado.

## Como rodar

1. Suba o PostgreSQL:
   ```bash
   docker compose up -d
   ```
2. Rode a aplicação:
   ```bash
   ./gradlew bootRun
   ```
3. A API sobe em `http://localhost:8080`.

## Como rodar os testes

```bash
./gradlew test
```

- `security`/`service` — testes unitários (geração/validação de JWT, regras de registro/login/refresh com repositórios mockados), não precisam de Docker.
- `integration` — testes de integração via MockMvc contra um PostgreSQL real (Testcontainers), cobrindo o fluxo completo de registro → login → acesso a `/profile` → 401 sem token → 403 em `/admin/users` sem a role `ROLE_ADMIN` → 200 depois de promover o usuário → fluxo de refresh token (incluindo rejeitar um access token usado como refresh).

> **Nota sobre o ambiente de desenvolvimento usado para este projeto**: neste sandbox específico, os testes de integração baseados em Testcontainers não executam pela mesma causa raiz observada nos projetos [3](../java-spring-kafka-pipeline-eventos-cliques), [5](../java-spring-selenium-painel-tarefas), [6](../java-spring-graphql-biblioteca) e [7](../java-spring-redis-encurtador-url). Os 11 testes unitários passam normalmente, tudo compila, e o fluxo completo (registro, login, acesso autenticado, 401/403, promoção a admin, refresh) foi validado manualmente rodando a aplicação de ponta a ponta.

## Endpoints principais

| Método | Rota             | Autenticação      | Descrição                                          |
|--------|-------------------|-------------------|-------------------------------------------------------|
| POST   | `/auth/register`  | pública           | Cria usuário com senha em hash (role padrão `ROLE_USER`) |
| POST   | `/auth/login`     | pública           | Autentica e retorna `{ accessToken, refreshToken }`     |
| POST   | `/auth/refresh`   | pública (refresh) | Troca um refresh token válido por um novo par de tokens |
| GET    | `/profile`        | qualquer usuário  | Dados do usuário autenticado                            |
| GET    | `/admin/users`    | `ROLE_ADMIN`      | Lista todos os usuários                                 |

## Exemplo de uso

```bash
# Cadastrar usuário
curl -s -X POST localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "supersecret123"}'

# Login
curl -s -X POST localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "supersecret123"}'
# {"accessToken": "...", "refreshToken": "..."}

# Acessar endpoint protegido
curl -s localhost:8080/profile -H "Authorization: Bearer <accessToken>"

# Renovar tokens
curl -s -X POST localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<refreshToken>"}'
```

Não há endpoint para promover um usuário a `ROLE_ADMIN` (fora do escopo do MVP — veja o `PLANNING.md`); para testar `/admin/users` localmente, insira a linha em `user_roles` diretamente no Postgres e faça login novamente (as roles são lidas no momento da emissão do token).

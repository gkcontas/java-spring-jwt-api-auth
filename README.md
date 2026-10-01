# API de Autenticação e Autorização

API de autenticação com Spring Security e JWT: cadastro, login, emissão de access token e refresh token, e endpoints protegidos por papel.

Access token e refresh token são JWTs assinados com a mesma chave, diferenciados por um claim `type`. O filtro de autenticação só aceita tokens de acesso e o endpoint de renovação só aceita tokens de refresh, então um não serve no lugar do outro.

## Tecnologias e bibliotecas

| | |
|---|---|
| Linguagem | Java 17 |
| Framework | Spring Boot 3.3, Spring Security 6 |
| Tokens | jjwt 0.13 (HMAC-SHA512) |
| Persistência | Spring Data JPA, PostgreSQL 16 |
| Migrations | Flyway |
| Validação | Bean Validation |
| Build | Gradle Kotlin DSL (wrapper `gradlew`) |
| Testes | JUnit 5, Mockito, Spring Security Test, Testcontainers |
| Apoio | Lombok |

## Pré-requisitos

- JDK 17 ou superior
- Docker

## Como rodar

```bash
docker compose up -d
```

```bash
./gradlew bootRun
```

A API fica em `http://localhost:8080`.

## Fluxo

```
POST /auth/register  →  senha com BCrypt  →  PostgreSQL (role padrão ROLE_USER)

POST /auth/login     →  valida credenciais  →  { accessToken, refreshToken }

Endpoint protegido   →  Authorization: Bearer <accessToken>
                     →  filtro valida assinatura, expiração e tipo
                     →  popula o SecurityContext com as roles do token

POST /auth/refresh   →  valida o refresh token  →  novo par de tokens
```

## Decisões de segurança

- Senhas guardadas apenas como hash BCrypt, nunca em texto plano.
- Mensagem de erro de login idêntica para e-mail inexistente e senha errada, para não permitir enumerar usuários.
- Access token de 15 minutos e refresh token de 7 dias, configuráveis em `app.jwt.access-token-ttl` e `app.jwt.refresh-token-ttl`.
- Sessão HTTP desligada (`STATELESS`): a autenticação é reconstruída do token a cada requisição.
- Respostas 401 e 403 em JSON padronizado, no mesmo formato do resto da API.

O segredo em `application.yml` existe só para rodar localmente. Em um ambiente real ele viria de variável de ambiente ou gerenciador de segredos.

## Endpoints

| Método | Rota | Acesso | Descrição |
|---|---|---|---|
| `POST` | `/auth/register` | público | Cria o usuário com a role `ROLE_USER` |
| `POST` | `/auth/login` | público | Retorna `accessToken` e `refreshToken` |
| `POST` | `/auth/refresh` | público | Troca um refresh token por um novo par |
| `GET` | `/profile` | autenticado | Dados do usuário do token |
| `GET` | `/admin/users` | `ROLE_ADMIN` | Lista todos os usuários |

## Exemplos de uso

```bash
curl -s -X POST localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "supersecret123"}'
```

```bash
curl -s -X POST localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "supersecret123"}'
```

```bash
curl -s localhost:8080/profile -H "Authorization: Bearer <accessToken>"
```

```bash
curl -s -X POST localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "<refreshToken>"}'
```

Para experimentar `/admin/users`, insira a role na tabela `user_roles` pelo banco e faça login de novo — as roles entram no token no momento da emissão.

## Testes

```bash
./gradlew test
```

19 testes: 11 unitários e 8 de integração contra um PostgreSQL em container, cobrindo o caminho completo de registro, login, acesso autenticado, 401 sem token, 403 sem a role e renovação de tokens.

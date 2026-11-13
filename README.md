# Auth Service (RBAC + JWT)

## Run
    cp .env.example .env   # set strong secrets
    npm install
    npm start              # Node >= 20.6

## Endpoints
| Method | Path | Access |
|---|---|---|
| POST | /auth/register | public (always role `user`) |
| POST | /auth/login | public |
| POST | /auth/refresh | refresh token (rotates) |
| POST | /auth/logout | refresh token |
| GET | /auth/me | any authenticated |
| GET | /admin/users | admin, moderator |
| PATCH | /admin/users/:id/role | admin |

## Try it
    curl -X POST localhost:4000/auth/login -H 'content-type: application/json' \
      -d '{"email":"admin@example.com","password":"ChangeMe123!"}'
    curl localhost:4000/admin/users -H "Authorization: Bearer <accessToken>"

## Protecting your other microservices
Other services only need `JWT_ACCESS_SECRET` (or switch to RS256 and share the public key)
and the `authenticate` + `authorize(...)` middleware from `src/middleware.js`.

## Production checklist
- Replace `src/store.js` with Postgres/Mongo; keep refresh-token records in Redis or the DB.
- Move to RS256/EdDSA with a JWKS endpoint so other services verify without the signing secret.
- Serve over HTTPS only; consider httpOnly+Secure+SameSite cookies for browser clients.
- Add email verification, password reset, account lockout, and audit logging.

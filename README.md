# MarketWars Authentication Service

JWT-based authentication with Google OAuth 2.0 and Redis-backed session tracking.

## Overview

This service authenticates users via Google OAuth 2.0 and issues signed JWTs. Each token is bound to a device fingerprint (MAC-derived hash) and a random serial. Active sessions are stored in Redis with TTL for validation, refresh, and logout.

## Core Features

- **Google OAuth 2.0**: `passport-google-oauth20` for secure login
- **JWT issuance/verification**: `jsonwebtoken` with HS256 secret
- **Redis session ledger**: token presence/expiry tracked server-side
- **Device binding**: token payload includes `macAddress` and `serial`
- **Session management**: refresh and logout endpoints

## Architecture

- `src/services/JwtAuthService.ts`: Passport strategy, OAuth callback, JWT middleware, refresh, logout
- `src/services/RedisService.ts`: Typed Redis client with helpers (setEx, sets, ttl, health)
- `src/routes/authRoutes.ts`: Auth router (`/auth/...`)
- `src/server.ts`: Express app, middleware, route wiring, graceful shutdown
- `src/config/env.ts`: Environment loading and validation

## API

Base path: `http://localhost:<PORT>`

- `GET /auth/google`: Start Google OAuth consent
- `GET /auth/google/callback`: OAuth callback → issues JWT, stores session, optional redirect to `CLIENT_APP_URL?token=<jwt>`
- `GET /auth/me`: Returns `{ user }` for a valid JWT (Authorization: Bearer)
- `POST /auth/refresh`: Returns new JWT and extends Redis TTL
- `POST /auth/logout`: Revokes the current token (deletes Redis key)
- `GET /auth/failure`: Returns `{ error: "Authentication failed" }`

### JWT Payload (issued on success)
```json
{
  "sub": "<google_profile_id>",
  "email": "<optional>",
  "name": "<optional>",
  "picture": "<optional>",
  "provider": "google",
  "macAddress": "<hash>",
  "serial": "<hex>",
  "iat": 1710000000,
  "exp": 1710003600
}
```

### Common Responses
- 200: success objects as described above
- 400: `{ error: "No token provided" }`
- 401: `{ error: "Invalid token" }` or `{ error: "Token expired or invalid" }`
- 500: `{ error: "Authentication failed" | "Token refresh failed" | "Logout failed" }`

## Environment Variables

Required:
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `OAUTH_CALLBACK_URL` (e.g. `http://localhost:3000/auth/google/callback`)
- `JWT_SECRET`

Optional:
- `PORT` (default: 3000)
- `NODE_ENV` (default: `development`)
- `JWT_EXPIRATION_TIME` (seconds; default: 3600)
- `CLIENT_APP_URL` (if set, OAuth success redirects with `?token=`)
- `REDIS_URL` (recommended in production; e.g. `redis://localhost:6379`)

## Running Locally (Windows PowerShell)

1) Install dependencies
```powershell
npm install
```

2) Create `.env`
```powershell
@"
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
OAUTH_CALLBACK_URL=http://localhost:3000/auth/google/callback
JWT_SECRET=your_secure_secret
REDIS_URL=redis://localhost:6379
"@ | Out-File -Encoding UTF8 .env
```

3) Start Redis (Docker)
```powershell
docker run -d --name marketwars-redis -p 6379:6379 redis:7-alpine
```

4) Start the service
```powershell
npm run dev
# App: http://localhost:3000
```

## Docker

Compose (development):
```powershell
docker-compose up --build
```

Compose (production profile):
```powershell
docker-compose --profile production up --build
```

Direct Docker build/run:
```powershell
docker build -t marketwars-auth-service .
docker run -p 3000:3000 --env-file .env --link marketwars-redis:redis marketwars-auth-service
```

## Usage Examples (curl)

Start OAuth:
```bash
curl -i http://localhost:3000/auth/google
```

Get current user:
```bash
curl -s -H "Authorization: Bearer <jwt>" http://localhost:3000/auth/me
```

Refresh token:
```bash
curl -s -X POST -H "Authorization: Bearer <jwt>" http://localhost:3000/auth/refresh
```

Logout:
```bash
curl -s -X POST -H "Authorization: Bearer <jwt>" http://localhost:3000/auth/logout
```

## Project Structure

```
.
├─ .env                 
└─ src/
   ├─ config/
   │  └─ env.ts
   ├─ routes/
   │  └─ authRoutes.ts
   ├─ services/
   │  ├─ JwtAuthService.ts
   │  └─ RedisService.ts
   └─ server.ts
```

## NPM Scripts

- `npm run dev`: Start dev server with live reload
- `npm run build`: TypeScript build to `dist/`
- `npm run start`: Run compiled server from `dist/`
- `npm run typecheck`: Type-only check
- `npm run docker:*`: Helper scripts for Docker/Compose

## Security Notes

- Keep `JWT_SECRET` long and random
- Use HTTPS in production; terminate TLS before the service
- Treat tokens as credentials; store them securely client-side
- Set proper CORS origins in production
- Configure `REDIS_URL` to a protected instance; avoid open Redis

## Troubleshooting

- OAuth redirect mismatch → ensure `OAUTH_CALLBACK_URL` matches Google Console
- 401 on protected routes → verify `Authorization: Bearer <jwt>` and Redis TTL
- Redis connection errors → confirm `REDIS_URL` and that the container/service is reachable
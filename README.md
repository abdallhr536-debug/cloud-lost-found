# ☁️ Cloud Lost & Found
Campus lost-and-found web app. **Zero dependencies**: Node.js ≥ 22.5 only (built-in HTTP server, SQLite, crypto).

## Features
Register/Login (JWT, scrypt) · report lost/found items with image · search + filters · item details with contact · resolve/delete (owner only) · smart match notifications.

## Run locally
    npm start          # http://localhost:3000   (no npm install needed)
    npm test           # 26 end-to-end API tests

Env vars (see `.env.example`): `PORT`, `JWT_SECRET` (**set a long random value in production**), `DB_FILE`, `UPLOAD_DIR`.

## Structure
    server.js        API + static server
    schema.sql       users, items, notifications
    public/index.html  frontend
    test.js          end-to-end tests

## API (all except /auth/* need `Authorization: Bearer <token>`)
| Method | Path | Notes |
|---|---|---|
| POST | /api/auth/register | {name,email,password} |
| POST | /api/auth/login | {email,password} |
| GET | /api/items | ?q=&type=lost\|found&mine=1 |
| GET | /api/items/:id | details + owner contact |
| POST | /api/items | multipart: name,type,location,date,description,image |
| PATCH | /api/items/:id/resolve | owner only |
| DELETE | /api/items/:id | owner only |
| GET | /api/notifications | latest 30 |
| POST | /api/notifications/read | mark all read |

## Push to GitHub
    git init
    git add .
    git commit -m "Cloud Lost & Found"
    git branch -M main
    git remote add origin https://github.com/<your-user>/cloud-lost-found.git
    git push -u origin main

## Deploy (Render / Railway)
Build command: *(none)* · Start command: `npm start` · add env `JWT_SECRET`, attach a persistent disk and set `DB_FILE=/data/lostfound.db`, `UPLOAD_DIR=/data/uploads`.

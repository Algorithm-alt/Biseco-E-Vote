# BISECO E-Vote

Prefectorial Election Website for Bisease Senior High School.

## Features

- **Voter Portal** - Code-based login, ballot casting, results viewing, receipt verification
- **Admin Dashboard** - Election/position/candidate management, voter codes, audit logs, announcements
- **Real-time Updates** - WebSocket-powered live vote broadcasting
- **Security** - bcrypt password hashing, TOTP 2FA, CSRF protection, rate limiting, audit logging
- **PWA Support** - Offline-capable with service worker

## Tech Stack

| Layer       | Technology                 |
| ----------- | -------------------------- |
| Runtime     | Node.js                    |
| Framework   | Express.js                 |
| Database    | MySQL (mysql2)             |
| Auth        | bcryptjs, speakeasy (TOTP) |
| Real-time   | ws (WebSocket)             |
| Email       | nodemailer                 |
| File Upload | multer                     |

## Quick Start

### Prerequisites

- Node.js 18+
- MySQL 8.0+

### Installation

```bash
# Clone repository
git clone <repo-url>
cd "Biseco E-Vote"

# Install dependencies
npm install

# Configure environment
cp .env.example .env  # Create .env from template (see below)
# Edit .env with your settings

# Start server
npm start
```

Server runs on `http://localhost:4000`

### Environment Variables

Create a `.env` file with the following:

```env
# Database
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=biseco_vote

# Session
SESSION_SECRET=your_128_char_hex_string
PORT=4000
NODE_ENV=development

# Admin (created on first run)
ADMIN_PASSWORD=secure_admin_password

# Email (Gmail SMTP for password reset)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
SMTP_FROM=BISECO E-Vote <noreply@biseco.edu.gh>

# Public URL (used in reset links)
APP_URL=http://localhost:4000
```

**Generate SESSION_SECRET:**

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Database Setup

Tables are **auto-created** on first run. The admin user is created with the password from `ADMIN_PASSWORD`.

## Project Structure

```
├── server.js              # Entry point (Express + WebSocket)
├── utils.js               # Shared utilities
├── config/
│   ├── db.js              # MySQL connection pool
│   └── mailer.js          # Nodemailer transporter
├── routes/
│   ├── auth.js            # Auth routes
│   ├── votes.js           # Voting routes
│   ├── admin.js           # Admin CRUD
│   └── announcements.js   # Announcement routes
├── views/                 # HTML pages (served as routes)
├── public/                # Static assets
│   ├── css/style.css
│   ├── js/app.js
│   ├── sw.js              # Service worker
│   └── images/
└── .env                   # Environment config
```

## API Endpoints

### Auth

- `POST /api/auth/login` - Voter login
- `POST /api/auth/admin/login` - Admin login
- `POST /api/auth/admin/2fa-setup` - 2FA setup
- `POST /api/auth/admin/verify-2fa` - 2FA verification
- `POST /api/auth/admin/change-password` - Change password
- `POST /api/auth/admin/forgot-password` - Request reset
- `POST /api/auth/admin/reset-password` - Reset password
- `POST /api/auth/logout` - Logout

### Voting

- `GET /api/votes/active-election` - Get active election
- `GET /api/votes/ballot` - Get ballot
- `POST /api/votes/cast` - Cast vote
- `GET /api/votes/results` - Get results
- `POST /api/votes/verify` - Verify receipt

### Admin (requires admin session)

- `GET/POST/PUT/DELETE /api/admin/elections` - Election CRUD
- `GET/POST/PUT/DELETE /api/admin/positions` - Position CRUD
- `GET/POST/PUT/DELETE /api/admin/candidates` - Candidate CRUD
- `GET/POST/PUT/DELETE /api/admin/voters` - Voter management
- `GET /api/admin/audit-logs` - Audit logs
- `GET/POST/PUT/DELETE /api/admin/announcements` - Announcements
- `POST /api/admin/generate-codes` - Bulk generate voter codes
- `POST /api/admin/import-voters` - CSV import

### Announcements

- `GET /api/announcements` - Public announcements

## Security Features

- **Rate Limiting** - 8 limiters (login, vote, admin actions, etc.)
- **Account Lockout** - 5 failed attempts = 15 min lockout
- **CSRF Protection** - Token required on all mutating requests
- **Security Headers** - CSP, HSTS, X-Frame-Options, etc.
- **Input Sanitization** - Trim + length limits on all inputs
- **Audit Logging** - All admin actions logged with IP

## Deployment

### Production Checklist

1. Set `NODE_ENV=production`
2. Use strong `SESSION_SECRET` (128-char hex)
3. Configure reverse proxy (nginx) with SSL
4. Set `trust proxy` in Express (auto-enabled in production)
5. Use dedicated MySQL user with minimal privileges
6. Store `.env` securely (never commit)

### Docker (optional)

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 4000
CMD ["npm", "start"]
```

## License

MIT

# Chirpy 🐦

A Twitter-like social media platform built with Go, featuring user authentication, real-time chirps (tweets), and premium membership capabilities.

## Features

- **User Authentication**: Secure user registration and login with JWT tokens
- **Refresh Tokens**: Extended session management with refresh token system
- **Chirps Management**: Create, read, and delete chirps (tweets)
- **User Profiles**: Update user information including email and password
- **Chirpy Red Membership**: Premium membership with webhook integration
- **Advanced Filtering**: Filter chirps by author and sort by date
- **Metrics Tracking**: Built-in request counting for analytics
- **RESTful API**: Clean, well-structured API endpoints

## Tech Stack

- **Language**: Go 1.23
- **Database**: PostgreSQL with SQLC for type-safe queries
- **Authentication**: JWT (JSON Web Tokens) with refresh tokens
- **Password Security**: bcrypt hashing
- **Database Migrations**: Goose
- **Environment Management**: godotenv

## Prerequisites

- Go 1.23 or higher
- PostgreSQL 12 or higher
- SQLC (`go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest`)
- Goose (`go install github.com/pressly/goose/v3/cmd/goose@latest`)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/olereon/Chirpy-boot.git
cd Chirpy-boot
```

2. Install dependencies:
```bash
go mod download
```

3. Set up environment variables by creating a `.env` file:
```env
DB_URL="postgres://username:password@localhost:5432/chirpy?sslmode=disable"
PLATFORM="dev"
JWT_SECRET="your-secret-key-here"
POLKA_KEY="your-polka-api-key"
```

4. Run database migrations:
```bash
goose -dir sql/schema postgres "${DB_URL}" up
```

5. Generate SQLC code:
```bash
sqlc generate
```

6. Build and run the application:
```bash
go build -o chirpy-boot
./chirpy-boot
```

The server will start on `http://localhost:8080`

## API Endpoints

### Health Check
- `GET /api/healthz` - Check if the server is running

### Authentication

#### Register User
```http
POST /api/users
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword"
}
```

#### Login
```http
POST /api/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword"
}
```

#### Refresh Token
```http
POST /api/refresh
Authorization: Bearer <refresh_token>
```

#### Revoke Token
```http
POST /api/revoke
Authorization: Bearer <refresh_token>
```

### User Management

#### Update User
```http
PUT /api/users
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "email": "newemail@example.com",
  "password": "newpassword"
}
```

### Chirps

#### Create Chirp
```http
POST /api/chirps
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "body": "This is my first chirp!"
}
```

#### Get All Chirps
```http
GET /api/chirps?author_id=<uuid>&sort=<asc|desc>
```
Query parameters (optional):
- `author_id`: Filter chirps by specific user
- `sort`: Sort order (`asc` or `desc`, default: `asc`)

#### Get Single Chirp
```http
GET /api/chirps/{chirpID}
```

#### Delete Chirp
```http
DELETE /api/chirps/{chirpID}
Authorization: Bearer <access_token>
```

### Premium Features

#### Polka Webhook (Chirpy Red Upgrade)
```http
POST /api/polka/webhooks
Authorization: ApiKey <polka_api_key>
Content-Type: application/json

{
  "event": "user.upgraded",
  "data": {
    "user_id": "<user_uuid>"
  }
}
```

### Admin Endpoints

#### View Metrics
```http
GET /admin/metrics
```

#### Reset Metrics
```http
POST /admin/reset
```
*Note: Only available in development mode*

## Project Structure

```
Chirpy-boot/
├── internal/
│   ├── auth/          # Authentication utilities (JWT, password hashing)
│   └── database/      # SQLC generated database code
├── sql/
│   ├── queries/       # SQL queries for SQLC
│   └── schema/        # Database migrations
├── main.go            # Application entry point
├── go.mod             # Go module definition
├── go.sum             # Go module checksums
├── sqlc.yaml          # SQLC configuration
└── .env               # Environment variables
```

## Database Schema

### Users Table
- `id` (UUID) - Primary key
- `created_at` (timestamp)
- `updated_at` (timestamp)
- `email` (text) - Unique
- `hashed_password` (text)
- `is_chirpy_red` (boolean) - Premium membership status

### Chirps Table
- `id` (UUID) - Primary key
- `created_at` (timestamp)
- `updated_at` (timestamp)
- `body` (text) - Chirp content
- `user_id` (UUID) - Foreign key to users

### Refresh Tokens Table
- `token` (text) - Primary key
- `created_at` (timestamp)
- `updated_at` (timestamp)
- `user_id` (UUID) - Foreign key to users
- `expires_at` (timestamp)
- `revoked_at` (timestamp) - Nullable

## Security Features

- **Password Hashing**: All passwords are hashed using bcrypt
- **JWT Authentication**: Stateless authentication with short-lived access tokens
- **Refresh Tokens**: Secure session management with revocable refresh tokens
- **API Key Authentication**: Webhook endpoints secured with API keys
- **Input Validation**: All inputs are validated before processing
- **Profanity Filter**: Automatic filtering of inappropriate content

## Development

### Running Tests
```bash
go test ./...
```

### Adding New Database Queries
1. Add your query to `sql/queries/users.sql`
2. Run `sqlc generate` to generate Go code
3. Use the generated functions in your handlers

### Adding New Migrations
```bash
goose -dir sql/schema create <migration_name> sql
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built as part of the Boot.dev backend course
- Uses the excellent SQLC tool for type-safe SQL
- Inspired by Twitter's simple yet powerful design

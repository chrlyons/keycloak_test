# Keycloak Authentication Test Project

This project provides a test suite and Postman collection for testing Keycloak authentication flows.

## Prerequisites

- Docker and Docker Compose
- Python 3.12 or higher
- Poetry (Python package manager)
- Postman (for API testing)

## Project Structure

```
.
├── docker-compose.yml      # Docker configuration for Keycloak and PostgreSQL
├── .env                    # Environment variables
├── tests/
│   └── test_auth.py        # Python test suite
└── postman/
    ├── postman-collection.json    # Postman API collection
    └── postman-environment.json   # Postman environment variables
```

## Environment Variables

```
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin
TEST_REALM_NAME=test-realm
TEST_CLIENT_ID=test-client
TEST_USERNAME=test-user
TEST_PASSWORD=test-password
```

## Setup

1. Install dependencies:
```bash
poetry install
```

2. Start Keycloak:
```bash
docker compose up -d
```

3. Wait for Keycloak to be ready (about 30 seconds)

## Running Tests

Run the Python test suite:
```bash
poetry run pytest tests/test_auth.py -v
```

## Using Postman Collection

1. Import both files from the `postman` directory into Postman:
   - `postman-collection.json`
   - `postman-environment.json`

2. Select the "Keycloak Local" environment

3. Run the requests in order:
   - Get Admin Token
   - Create Realm
   - Create Client
   - Get Clients (gets client UUID)
   - Generate Client Secret
   - Create User
   - Password Grant Token
   - Client Credentials Token
   - Refresh Token

The collection includes test scripts that automatically set environment variables from responses.

## Authentication Flows Tested

1. Password Grant Flow
   - Used for direct user authentication
   - Requires username and password
   - Returns access and refresh tokens

2. Client Credentials Flow
   - Used for service-to-service authentication
   - Requires client_id and client_secret
   - Returns access token

3. Refresh Token Flow
   - Used to get new access token using refresh token
   - Requires refresh token from password grant

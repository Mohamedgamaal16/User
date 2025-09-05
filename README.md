
# Spring Boot JWT Authentication API

This is a Spring Boot application that provides a secure REST API for user authentication and management using JSON Web Tokens (JWT). It supports **access tokens** and **refresh tokens** for secure, stateless authentication. The API includes features like user registration, login, admin account creation, user data retrieval, role-based access control, refresh token support, and rate limiting.

---

## Features

* **JWT-Based Authentication**

  * Access Tokens: Expire after 30 minutes.
  * Refresh Tokens: Expire after 7 days.
  * Tokens are signed with HS256 using a secure secret.

* **Refresh Token Endpoint**

  * `/api/refresh`: Issues a new access token when a valid refresh token is provided.
  * Ensures that users do not have to log in again until the refresh token expires.

* **Role-Based Authorization**

  * Supports `CUSTOMER` and `ADMIN` roles.
  * Admin-only endpoints protected with `@PreAuthorize("hasRole('ADMIN')")`.

* **User Management**

  * Register users (`/api/sign-up/user`) and admins (`/api/sign-up/admin`).
  * Retrieve user data by email (`/api/user/{email}`) or current user (`/api/user/current`).
  * Supports profile image uploads (stored as byte arrays in the database).

* **Password Encryption**

  * Passwords securely hashed using `BCryptPasswordEncoder`.

* **Rate Limiting**

  * `/api/login`: max 5 requests per minute.
  * `/api/sign-up/user`: max 3 requests per minute.

* **Default Admin Account**

  * Creates a default admin on startup if none exists.
  * Credentials configurable via environment variables.

* **Security Filter**

  * `JwtRequestFilter` validates tokens for protected endpoints and sets authentication in the Spring Security context.

---

## Project Structure

* **JwtRequestFilter**: Validates tokens for each request.
* **AuthServiceImpl**: Manages user and admin creation, retrieval, and refresh token logic.
* **UserDetailsServiceImpl**: Loads user details for authentication.
* **AuthController**: Exposes login, sign-up, refresh, and user retrieval endpoints.
* **JwtUtil**: Generates, validates, and extracts claims from tokens.
* **Rate Limiting**: Configured with Resilience4j for brute-force protection.

---

## Setup Instructions

(unchanged from your version, just kept consistent)

---

## API Endpoints

| Method | Endpoint             | Description                                                 | Required Role      |
| ------ | -------------------- | ----------------------------------------------------------- | ------------------ |
| POST   | `/api/login`         | Authenticate user and return **access** + **refresh token** | None               |
| POST   | `/api/sign-up/user`  | Register a new user (CUSTOMER)                              | None               |
| POST   | `/api/sign-up/admin` | Register a new admin                                        | ADMIN              |
| GET    | `/api/user/{email}`  | Retrieve user by email                                      | Authenticated user |
| GET    | `/api/user/current`  | Retrieve current user based on JWT                          | Authenticated user |
| POST   | `/api/refresh`       | Generate a new access token using refresh token             | Authenticated user |

---

### Example Requests

 https://.postman.co/workspace/My-Workspace~ea8525f4-631b-48a4-8869-ffae1f0aa998/folder/32005719-c1e7fb6d-1148-4355-9488-27d05639cca0?action=share&creator=32005719&ctx=documentation
---

## Security Considerations

* **JWT Validation**: Signature, expiration, and username checks for both access and refresh tokens.
* **Refresh Tokens**: Stored securely (HTTP-only cookies recommended in production).
* **Password Hashing**: Uses BCrypt for secure storage.
* **Rate Limiting**: Protects sensitive endpoints against brute-force attacks.
* **Role-Based Access**: Admin endpoints restricted to `ROLE_ADMIN`.
* **Image Upload Security**: Validate file type and size.
* **Email Verification**: Consider adding verification for new sign-ups.

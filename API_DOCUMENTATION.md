# Senfi API Documentation

## Overview
Senfi API is a RESTful API for managing campaigns and signatures at Sharif University.

## Base URL
- **Development**: `http://127.0.0.1:8000`
- **Production**: `https://senfi.sharif.ir`

## Authentication
The API uses JWT (JSON Web Tokens) for authentication.

### Login
```http
POST /api/auth/login/
Content-Type: application/json

{
    "email": "user@sharif.edu",
    "password": "password123"
}
```

**Response:**
```json
{
    "success": true,
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "email": "user@sharif.edu",
        "role": "student",
        "unit": "computer"
    }
}
```

### Using JWT Token
Include the token in the Authorization header:
```http
Authorization: Bearer <your_jwt_token>
```

## Endpoints

### Authentication
- `POST /api/auth/login/` - User login
- `POST /api/auth/register/` - User registration
- `POST /api/auth/refresh/` - Refresh JWT token
- `GET /api/auth/user/` - Get current user info
- `GET /api/auth/validate/` - Validate JWT token

### Campaigns
- `POST /api/campaigns/submit/` - Submit new campaign
- `GET /api/campaigns/approved/` - Get approved campaigns
- `GET /api/campaigns/rejected/` - Get rejected campaigns
- `GET /api/campaigns/pending/` - Get pending campaigns (admin)
- `POST /api/campaigns/approve/` - Approve/reject campaign (admin)
- `PUT /api/campaigns/{id}/status/` - Update campaign status (admin)

### Signatures
- `POST /api/campaigns/{id}/sign/` - Sign a campaign
- `GET /api/campaigns/{id}/signatures/` - Get campaign signatures
- `GET /api/campaigns/{id}/check-signature/` - Check if user signed
- `GET /api/user/signed-campaigns/` - Get user's signed campaigns

### Users (Admin)
- `GET /api/users/` - List all users (admin)
- `GET /api/users/{id}/` - Get user details (admin)
- `PUT /api/users/{id}/role/` - Update user role (admin)
- `GET /api/users/{id}/signed-campaigns/` - Get user's signed campaigns (admin)

## Interactive Documentation
- **Swagger UI**: `http://127.0.0.1:8000/api/docs/`
- **ReDoc**: `http://127.0.0.1:8000/api/redoc/`
- **OpenAPI Schema**: `http://127.0.0.1:8000/api/schema/`

## Rate Limiting
- Login: 5 attempts per minute per IP
- Email verification: 3 attempts per minute per IP

## Error Responses
All errors follow this format:
```json
{
    "success": false,
    "detail": "Error message"
}
```

## Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Too Many Requests
- `500` - Internal Server Error

## Security Features
- JWT authentication with token rotation
- Rate limiting on sensitive endpoints
- Input validation and sanitization
- CORS protection
- Security headers
- Request logging
- Error handling

## Development
To run the development server:
```bash
python3 manage.py runserver 127.0.0.1:8000
```

To generate API schema:
```bash
python3 manage.py spectacular --file schema.yml
``` 
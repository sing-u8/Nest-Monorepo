# Configuration Management

This directory contains the configuration management system for the authentication service. The system provides type-safe, validated configuration with environment-specific presets.

## Overview

The configuration system uses:
- **Class-validator** for runtime validation
- **Class-transformer** for type conversion
- **Environment variables** for configuration values
- **Environment-specific presets** for different deployment scenarios
- **NestJS ConfigModule** integration

## Files Structure

```
config/
├── app.config.ts              # Main application configuration with validation
├── jwt.config.ts              # JWT-specific configuration
├── oauth.config.ts            # OAuth providers configuration
├── database.config.ts         # Database configuration
├── password-hashing.config.ts # Password hashing configuration
├── rate-limiting.config.ts    # Rate limiting configuration
├── app.config.spec.ts         # Configuration validation tests
├── index.ts                   # Configuration exports
└── README.md                  # This file
```

## Usage

### Basic Usage

```typescript
import { getAppConfig } from './config/app.config';

// Get validated configuration
const config = getAppConfig();

console.log(`Starting server on port ${config.PORT}`);
console.log(`Database: ${config.DATABASE_HOST}:${config.DATABASE_PORT}`);
```

### NestJS Integration

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { appConfig } from './config/app.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [appConfig],
      isGlobal: true,
      validate: (config) => {
        // Validation is handled automatically by appConfig
        return config;
      },
    }),
  ],
})
export class AppModule {}
```

### Using in Services

```typescript
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from './config/app.config';

@Injectable()
export class SomeService {
  constructor(private configService: ConfigService) {}

  getJwtSecret(): string {
    return this.configService.get<string>('app.JWT_SECRET');
  }

  getDatabaseConfig() {
    const config = this.configService.get<AppConfig>('app');
    return {
      host: config.DATABASE_HOST,
      port: config.DATABASE_PORT,
      username: config.DATABASE_USERNAME,
      password: config.DATABASE_PASSWORD,
      database: config.DATABASE_NAME,
    };
  }
}
```

## Environment Variables

### Required Variables

The following environment variables are required for the application to start:

```bash
# Application
NODE_ENV=development|staging|production|test

# Security - JWT
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key

# Database
DATABASE_USERNAME=your_db_user
DATABASE_PASSWORD=your_db_password
DATABASE_NAME=your_database_name
```

### Optional Variables

The following variables have default values but can be overridden:

```bash
# Application Settings
PORT=3000
APP_NAME=Auth Service
API_PREFIX=api/v1

# Database
DATABASE_TYPE=postgres
DATABASE_HOST=localhost
DATABASE_PORT=5432

# JWT Settings
JWT_ISSUER=auth-service
JWT_AUDIENCE=auth-service-users
JWT_ACCESS_TOKEN_EXPIRATION=15m
JWT_REFRESH_TOKEN_EXPIRATION=7d

# Security
SECURITY_ENABLE_RATE_LIMITING=true
SECURITY_ENABLE_HELMET=true
SECURITY_ENABLE_MTLS=false

# Logging
LOG_LEVEL=info
LOG_ENABLE_CONSOLE=true
LOG_ENABLE_FILE=false
```

### OAuth Variables (Optional)

```bash
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/api/v1/auth/social/google/callback

# Apple Sign In
APPLE_CLIENT_ID=your.apple.client.id
APPLE_TEAM_ID=YOUR_TEAM_ID
APPLE_KEY_ID=YOUR_KEY_ID
APPLE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY\n-----END PRIVATE KEY-----
APPLE_CALLBACK_URL=http://localhost:3000/api/v1/auth/social/apple/callback
```

## Environment Files

The project supports multiple environment files:

1. **`.env.example`** - Template with all available variables and documentation
2. **`.env.development`** - Development-specific settings
3. **`.env.test`** - Testing-specific settings
4. **`.env.production`** - Production-specific settings (requires real secrets)
5. **`.env.local`** - Local overrides (not committed to git)
6. **`.env`** - Default environment file

### Loading Priority

Environment files are loaded in this order (later files override earlier ones):
1. `.env`
2. `.env.local`
3. `.env.${NODE_ENV}`
4. `.env.${NODE_ENV}.local`

## Environment Presets

The configuration system includes environment-specific presets:

### Development
- Database synchronization enabled
- Detailed logging enabled
- CORS enabled for all origins
- Rate limiting disabled
- Security relaxed for development ease

### Test
- Fast settings for testing
- Minimal logging
- In-memory database options
- Security features disabled
- Short token expiration times

### Staging
- Production-like settings
- Monitoring enabled
- File logging enabled
- Security features enabled
- CORS restricted

### Production
- Maximum security
- mTLS enabled
- File logging only
- Strict CORS policy
- Monitoring and metrics enabled

## Configuration Validation

All configuration is validated at startup using class-validator decorators:

```typescript
export class AppConfig {
  @IsEnum(Environment)
  NODE_ENV: Environment = Environment.DEVELOPMENT;

  @IsNumber()
  @Min(1000)
  @Max(65535)
  @Transform(({ value }) => parseInt(value, 10))
  PORT: number = 3000;

  @IsString()
  JWT_SECRET: string;

  @IsUrl()
  @IsOptional()
  GOOGLE_CALLBACK_URL?: string;

  // ... more validations
}
```

### Validation Features

- **Type conversion**: Strings from environment variables are converted to appropriate types
- **Range validation**: Numeric values are validated against acceptable ranges
- **Format validation**: URLs, emails, and other formats are validated
- **Required vs optional**: Clear distinction between required and optional variables
- **Custom validation**: Complex validation logic for specific business rules

## Error Handling

The configuration system provides detailed error messages for validation failures:

```
Configuration validation failed:
PORT: must not be less than 1000, must not be greater than 65535
JWT_SECRET: should not be empty
DATABASE_USERNAME: should not be empty
GOOGLE_CALLBACK_URL: must be a URL address
```

## Security Considerations

### Production Security

1. **Secrets Management**: Never commit production secrets to version control
2. **Environment Isolation**: Use different secrets for each environment
3. **Key Rotation**: Regularly rotate JWT secrets and OAuth credentials
4. **Access Control**: Limit access to production environment variables

### Secret Generation

Generate secure secrets using:

```bash
# JWT secrets (64 characters)
openssl rand -base64 64

# Random passwords
openssl rand -base64 32

# UUIDs for identifiers
uuidgen
```

### Environment Variable Security

- Use secret management systems in production (AWS Secrets Manager, Azure Key Vault, etc.)
- Never log sensitive configuration values
- Use read-only access for application runtime
- Implement secret rotation procedures

## Testing

Run configuration tests:

```bash
# Unit tests for configuration validation
npm test -- --testPathPattern=app.config.spec.ts

# Test with different environment variables
NODE_ENV=test npm test -- --testPathPattern=app.config.spec.ts
```

## Troubleshooting

### Common Issues

1. **Validation Errors**: Check that all required environment variables are set
2. **Type Conversion**: Ensure numeric values are valid numbers
3. **URL Format**: Check that callback URLs are properly formatted
4. **Environment Loading**: Verify the correct `.env` file is being loaded

### Debug Configuration

Enable configuration debugging:

```typescript
import { getAppConfig } from './config/app.config';

try {
  const config = getAppConfig();
  console.log('Configuration loaded successfully');
} catch (error) {
  console.error('Configuration validation failed:', error.message);
  process.exit(1);
}
```

### Environment Verification

Verify your environment setup:

```bash
# Check environment variables
printenv | grep -E "(NODE_ENV|JWT_|DATABASE_|GOOGLE_|APPLE_)"

# Validate configuration
npm run config:validate
```

## Examples

See the test files and example environment files for comprehensive usage examples:

- `app.config.spec.ts` - Configuration validation tests
- `.env.example` - Complete example with all variables
- `.env.development` - Development setup example
- `.env.production` - Production setup template
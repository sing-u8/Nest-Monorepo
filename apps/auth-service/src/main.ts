import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app/app.module';
import helmet from 'helmet';
import * as compression from 'compression';

/**
 * Application Bootstrap
 * 
 * Configures and starts the NestJS authentication service with
 * comprehensive security, validation, and documentation setup.
 */
async function bootstrap() {
  // Create application instance
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug', 'verbose'],
    cors: false, // We'll configure CORS separately
  });

  // Get configuration service
  const configService = app.get(ConfigService);
  const appConfig = configService.get('app');
  const securityConfig = configService.get('security');

  // Global prefix
  const globalPrefix = appConfig.apiPrefix || 'api';
  app.setGlobalPrefix(globalPrefix);

  // API versioning
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  }));

  // Compression middleware
  app.use(compression());

  // Global validation pipe with comprehensive configuration
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
      disableErrorMessages: appConfig.isProduction,
      validationError: {
        target: false,
        value: false,
      },
    }),
  );

  // CORS configuration using SecurityService
  const corsOptions = {
    origin: (origin: string, callback: (err: Error | null, allow?: boolean) => void) => {
      const allowedOrigins = securityConfig.cors.allowedOrigins || [];
      
      // Allow requests with no origin (mobile apps, etc.)
      if (!origin) return callback(null, true);
      
      // Check if origin is in allowed list
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      // Check if origin matches patterns in production
      if (appConfig.isProduction) {
        const allowedPatterns = securityConfig.cors.allowedPatterns || [];
        const isAllowed = allowedPatterns.some((pattern: string) => {
          const regex = new RegExp(pattern);
          return regex.test(origin);
        });
        
        if (isAllowed) {
          return callback(null, true);
        }
      }

      Logger.warn(`CORS blocked origin: ${origin}`);
      callback(new Error('CORS policy violation'), false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Origin',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Authorization',
      'X-Device-ID',
      'X-Client-Version',
    ],
    exposedHeaders: [
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
    ],
    credentials: true,
    maxAge: 86400, // 24 hours
  };

  app.enableCors(corsOptions);

  // Swagger documentation configuration
  if (!appConfig.isProduction) {
    const swaggerConfig = new DocumentBuilder()
      .setTitle('Auth Service API')
      .setDescription(
        'Authentication and user management service API documentation.\n\n' +
        'This service provides comprehensive authentication functionality including:\n' +
        '- User registration and login\n' +
        '- JWT token management with refresh tokens\n' +
        '- Social authentication (Google, Apple)\n' +
        '- Profile management\n' +
        '- Rate limiting and security features\n' +
        '- mTLS authentication for service-to-service communication'
      )
      .setVersion('1.0.0')
      .addBearerAuth(
        {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          name: 'JWT',
          description: 'Enter JWT token',
          in: 'header',
        },
        'JWT-auth'
      )
      .addApiKey(
        {
          type: 'apiKey',
          name: 'X-Device-ID',
          in: 'header',
          description: 'Device identifier for tracking and security',
        },
        'device-id'
      )
      .addServer(
        `http://localhost:${appConfig.port}`,
        'Local development server'
      )
      .addTag('Authentication', 'User authentication and token management')
      .addTag('Social Auth', 'OAuth integration with Google and Apple')
      .addTag('Profile', 'User profile management')
      .addTag('Health', 'Application health checks')
      .build();

    const document = SwaggerModule.createDocument(app, swaggerConfig, {
      operationIdFactory: (controllerKey: string, methodKey: string) =>
        `${controllerKey}_${methodKey}`,
    });

    SwaggerModule.setup(`${globalPrefix}/docs`, app, document, {
      swaggerOptions: {
        persistAuthorization: true,
        displayRequestDuration: true,
        docExpansion: 'none',
        filter: true,
        showRequestHeaders: true,
        syntaxHighlight: {
          theme: 'arta',
        },
      },
      customSiteTitle: 'Auth Service API Documentation',
      customfavIcon: '/favicon.ico',
      customCssUrl: '/swagger-ui-custom.css',
    });

    Logger.log(
      `📚 API documentation available at: http://localhost:${appConfig.port}/${globalPrefix}/docs`
    );
  }

  // Graceful shutdown handling
  process.on('SIGTERM', () => {
    Logger.log('SIGTERM received, starting graceful shutdown...');
    app.close().then(() => {
      Logger.log('Application closed gracefully');
      process.exit(0);
    });
  });

  process.on('SIGINT', () => {
    Logger.log('SIGINT received, starting graceful shutdown...');
    app.close().then(() => {
      Logger.log('Application closed gracefully');
      process.exit(0);
    });
  });

  // Application shutdown hooks
  app.enableShutdownHooks();

  // Start application
  const port = appConfig.port || 3000;
  await app.listen(port, '0.0.0.0');

  // Startup logs
  Logger.log(`🚀 Auth Service is running on: http://localhost:${port}/${globalPrefix}`);
  Logger.log(`🌍 Environment: ${appConfig.nodeEnv}`);
  Logger.log(`🔒 Security features enabled`);
  Logger.log(`📊 Health checks available at: http://localhost:${port}/health`);
  
  if (!appConfig.isProduction) {
    Logger.log(`🔧 Development mode: Additional logging and debugging enabled`);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  Logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  Logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

bootstrap().catch((error) => {
  Logger.error('Application failed to start:', error);
  process.exit(1);
});

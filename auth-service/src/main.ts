/**
 * NestJS Authentication Service - Main Bootstrap
 * 
 * Production-ready application bootstrap with comprehensive configuration:
 * - Global middleware, filters, and pipes
 * - Swagger API documentation
 * - Security headers and CORS
 * - Graceful shutdown handling
 * - Health checks and monitoring
 * - Request/response logging
 */

import { Logger, ValidationPipe, VersioningType } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app/app.module';
import { AppConfig } from '@auth/infrastructure';
import { GlobalExceptionFilter } from './app/filters/global-exception.filter';
import { LoggingInterceptor } from './app/interceptors/logging.interceptor';
import { MetricsInterceptor } from '@auth/infrastructure';
import helmet from 'helmet';
import * as compression from 'compression';

/**
 * Bootstrap function to initialize and configure the NestJS application
 */
async function bootstrap(): Promise<void> {
  const logger = new Logger('Bootstrap');

  try {
    // Create NestJS application instance
    const app = await NestFactory.create(AppModule, {
      // Enable CORS during application creation
      cors: true,
      // Configure logger levels based on environment
      logger: process.env.NODE_ENV === 'production' 
        ? ['error', 'warn'] 
        : ['error', 'warn', 'log', 'debug', 'verbose'],
    });

    // Get configuration service
    const configService = app.get(ConfigService);
    const appConfig = configService.get<AppConfig>('app');

    // Configure global settings
    await configureGlobalSettings(app, appConfig);

    // Configure security
    await configureSecurity(app, appConfig);

    // Configure API documentation
    await configureSwagger(app, appConfig);

    // Configure monitoring and health checks
    await configureMonitoring(app, appConfig);

    // Configure graceful shutdown
    configureShutdownHooks(app);

    // Start the application
    const port = appConfig.PORT;
    await app.listen(port, '0.0.0.0');

    // Log startup information
    logStartupInfo(appConfig, port);

  } catch (error) {
    logger.error('Failed to bootstrap application', error);
    process.exit(1);
  }
}

/**
 * Configure global application settings
 */
async function configureGlobalSettings(app: any, config: AppConfig): Promise<void> {
  const logger = new Logger('GlobalSettings');

  // Set global API prefix
  app.setGlobalPrefix(config.API_PREFIX, {
    exclude: [
      // Exclude health check and metrics from API prefix
      { path: config.MONITORING_HEALTH_CHECK_PATH || '/health', method: 'GET' },
      { path: config.MONITORING_METRICS_PATH || '/metrics', method: 'GET' },
      { path: '/', method: 'GET' }, // Root endpoint
    ],
  });

  // Enable API versioning
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
    prefix: 'v',
  });

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      // Automatically transform payloads to DTO instances
      transform: true,
      // Strip properties that don't have decorators
      whitelist: true,
      // Throw error if non-whitelisted properties are present
      forbidNonWhitelisted: true,
      // Automatically transform primitive types
      transformOptions: {
        enableImplicitConversion: true,
      },
      // Detailed error messages in development
      disableErrorMessages: config.NODE_ENV === 'production',
      // Custom error message format
      exceptionFactory: (errors) => {
        const formattedErrors = errors.map(error => ({
          field: error.property,
          errors: Object.values(error.constraints || {}),
          value: error.value,
        }));
        return {
          statusCode: 400,
          message: 'Validation failed',
          errors: formattedErrors,
        };
      },
    })
  );

  // Enable compression for better performance
  app.use(compression({
    threshold: 1024, // Only compress if response > 1KB
    level: 6, // Compression level (1-9)
    filter: (req, res) => {
      // Don't compress responses if the client doesn't support it
      if (req.headers['x-no-compression']) {
        return false;
      }
      // Use compression filter function
      return compression.filter(req, res);
    },
  }));

  // Global exception filter
  app.useGlobalFilters(new GlobalExceptionFilter(app.get(ConfigService)));

  // Global interceptors
  app.useGlobalInterceptors(
    new LoggingInterceptor(app.get(ConfigService)),
    // Enable metrics collection if configured
    ...(config.MONITORING_ENABLE_METRICS ? [app.get(MetricsInterceptor)] : []),
  );

  logger.log('Global settings configured successfully');
}

/**
 * Configure application security
 */
async function configureSecurity(app: any, config: AppConfig): Promise<void> {
  const logger = new Logger('Security');

  // Configure Helmet for security headers
  if (config.SECURITY_ENABLE_HELMET) {
    app.use(helmet({
      // Customize CSP for development vs production
      contentSecurityPolicy: config.NODE_ENV === 'production' ? {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        },
      } : false, // Disable CSP in development
      // Hide X-Powered-By header
      hidePoweredBy: true,
      // Enable HSTS in production
      hsts: config.NODE_ENV === 'production' ? {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
      } : false,
    }));
  }

  // Configure CORS
  if (config.API_ENABLE_CORS) {
    const corsOrigins = config.API_CORS_ORIGIN 
      ? config.API_CORS_ORIGIN.split(',').map(origin => origin.trim())
      : true; // Allow all origins in development

    app.enableCors({
      origin: corsOrigins,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'X-API-Key',
        'X-Client-Version',
        'X-Request-ID',
      ],
      exposedHeaders: [
        'X-Total-Count',
        'X-Page-Count',
        'X-Rate-Limit-Remaining',
        'X-Rate-Limit-Reset',
      ],
      credentials: true,
      maxAge: 86400, // 24 hours
      optionsSuccessStatus: 200,
    });
  }

  logger.log('Security configuration applied successfully');
}

/**
 * Configure Swagger API documentation
 */
async function configureSwagger(app: any, config: AppConfig): Promise<void> {
  const logger = new Logger('Swagger');

  // Only enable Swagger in development and staging
  if (config.NODE_ENV === 'production') {
    logger.log('Swagger disabled in production environment');
    return;
  }

  const swaggerConfig = new DocumentBuilder()
    .setTitle(config.APP_NAME || 'Auth Service')
    .setDescription(config.APP_DESCRIPTION || 'NestJS Authentication Service API')
    .setVersion(config.APP_VERSION || '1.0.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter JWT token',
        name: 'Authorization',
        in: 'header',
      },
      'JWT'
    )
    .addApiKey(
      {
        type: 'apiKey',
        name: 'X-API-Key',
        in: 'header',
        description: 'API Key for service-to-service authentication',
      },
      'API-Key'
    )
    .addServer(`http://localhost:${config.PORT}`, 'Local Development')
    .addServer(`https://api-staging.yourapp.com`, 'Staging Environment')
    .addServer(`https://api.yourapp.com`, 'Production Environment')
    .addTag('Authentication', 'User authentication and registration')
    .addTag('Profile', 'User profile management')
    .addTag('OAuth', 'Social login with Google and Apple')
    .addTag('Health', 'Application health checks and monitoring')
    .addTag('Metrics', 'Application metrics and performance monitoring')
    .addTag('Alerting', 'Alert management and security notifications')
    .setContact('API Support', 'https://yourapp.com/support', 'support@yourapp.com')
    .setLicense('MIT', 'https://opensource.org/licenses/MIT')
    .setExternalDoc('API Guide', 'https://docs.yourapp.com/api')
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  
  // Serve Swagger documentation
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
      tagsSorter: 'alpha',
      operationsSorter: 'alpha',
      docExpansion: 'none',
      filter: true,
      showRequestHeaders: true,
      showCommonExtensions: true,
    },
    customCss: `
      .swagger-ui .topbar { display: none; }
      .swagger-ui .info .title { color: #3b82f6; }
    `,
    customSiteTitle: `${config.APP_NAME} - API Documentation`,
  });

  logger.log('Swagger documentation available at /docs');
}

/**
 * Configure monitoring and health checks
 */
async function configureMonitoring(app: any, config: AppConfig): Promise<void> {
  const logger = new Logger('Monitoring');

  // Health check endpoint will be handled by the health module
  // Metrics endpoint will be handled by the metrics module
  
  logger.log('Monitoring endpoints configured');
}

/**
 * Configure graceful shutdown hooks
 */
function configureShutdownHooks(app: any): void {
  const logger = new Logger('Shutdown');

  // Graceful shutdown on SIGTERM
  process.on('SIGTERM', async () => {
    logger.log('SIGTERM received, starting graceful shutdown');
    await gracefulShutdown(app, 'SIGTERM');
  });

  // Graceful shutdown on SIGINT (Ctrl+C)
  process.on('SIGINT', async () => {
    logger.log('SIGINT received, starting graceful shutdown');
    await gracefulShutdown(app, 'SIGINT');
  });

  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    gracefulShutdown(app, 'uncaughtException');
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    gracefulShutdown(app, 'unhandledRejection');
  });
}

/**
 * Perform graceful shutdown
 */
async function gracefulShutdown(app: any, signal: string): Promise<void> {
  const logger = new Logger('Shutdown');
  
  try {
    logger.log(`Graceful shutdown initiated by ${signal}`);
    
    // Set a timeout for the shutdown process
    const shutdownTimeout = setTimeout(() => {
      logger.error('Forced shutdown due to timeout');
      process.exit(1);
    }, 10000); // 10 seconds timeout

    // Close the NestJS application
    await app.close();
    
    clearTimeout(shutdownTimeout);
    logger.log('Application closed successfully');
    process.exit(0);
    
  } catch (error) {
    logger.error('Error during graceful shutdown:', error);
    process.exit(1);
  }
}

/**
 * Log startup information
 */
function logStartupInfo(config: AppConfig, port: number): void {
  const logger = new Logger('Startup');
  
  const baseUrl = `http://localhost:${port}`;
  const apiUrl = `${baseUrl}/${config.API_PREFIX}`;
  
  logger.log('🚀 Application started successfully!');
  logger.log(`📱 App Name: ${config.APP_NAME}`);
  logger.log(`🌍 Environment: ${config.NODE_ENV}`);
  logger.log(`🔗 Server URL: ${baseUrl}`);
  logger.log(`🔌 API Base URL: ${apiUrl}`);
  
  if (config.NODE_ENV !== 'production') {
    logger.log(`📚 API Documentation: ${baseUrl}/docs`);
  }
  
  if (config.MONITORING_ENABLE_HEALTH_CHECK) {
    logger.log(`💚 Health Check: ${baseUrl}${config.MONITORING_HEALTH_CHECK_PATH}`);
  }
  
  if (config.MONITORING_ENABLE_METRICS) {
    logger.log(`📊 Metrics: ${baseUrl}${config.MONITORING_METRICS_PATH}`);
  }
  
  logger.log('✅ All systems ready!');
}

// Start the application
bootstrap().catch((error) => {
  const logger = new Logger('Bootstrap');
  logger.error('Application failed to start:', error);
  process.exit(1);
});

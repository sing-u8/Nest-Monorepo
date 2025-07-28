import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule, getDataSourceToken } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { DatabaseModule } from '../database.module';
import { DatabaseHealthService } from '../health/database-health.service';
import { DatabaseHealthController } from '../health/database-health.controller';
import { UserEntity } from '../entities/user.entity';
import { TokenEntity } from '../entities/token.entity';
import { AuthSessionEntity } from '../entities/auth-session.entity';

describe('DatabaseModule Integration Tests', () => {
  let module: TestingModule;
  let dataSource: DataSource;
  let healthService: DatabaseHealthService;
  let healthController: DatabaseHealthController;

  beforeAll(async () => {
    // Set test environment variables
    process.env['NODE_ENV'] = 'test';
    process.env['DB_HOST'] = 'localhost';
    process.env['DB_PORT'] = '5432';
    process.env['DB_USERNAME'] = 'test_user';
    process.env['DB_PASSWORD'] = 'test_password';
    process.env['DB_DATABASE'] = 'test_auth_db';
    process.env['DB_SYNCHRONIZE'] = 'true';
    process.env['DB_DROP_SCHEMA'] = 'true';
    process.env['DB_POOL_MAX'] = '5';
    process.env['DB_POOL_MIN'] = '1';

    module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: '.env.test',
        }),
        DatabaseModule,
      ],
    }).compile();

    dataSource = module.get<DataSource>(getDataSourceToken());
    healthService = module.get<DatabaseHealthService>(DatabaseHealthService);
    healthController = module.get<DatabaseHealthController>(DatabaseHealthController);
  });

  afterAll(async () => {
    if (dataSource?.isInitialized) {
      await dataSource.destroy();
    }
    await module.close();
  });

  describe('Database Connection', () => {
    it('should initialize data source successfully', () => {
      expect(dataSource).toBeDefined();
      expect(dataSource.isInitialized).toBe(true);
    });

    it('should have correct database configuration', () => {
      expect(dataSource.options.type).toBe('postgres');
      expect(dataSource.options.host).toBe('localhost');
      expect(dataSource.options.port).toBe(5432);
      expect(dataSource.options.database).toBe('test_auth_db');
    });

    it('should have all entities registered', () => {
      const entityMetadatas = dataSource.entityMetadatas;
      const entityNames = entityMetadatas.map(metadata => metadata.name);
      
      expect(entityNames).toContain('UserEntity');
      expect(entityNames).toContain('TokenEntity');
      expect(entityNames).toContain('AuthSessionEntity');
    });

    it('should execute basic queries', async () => {
      const result = await dataSource.query('SELECT 1 as test');
      expect(result).toEqual([{ test: 1 }]);
    });
  });

  describe('Connection Pool Configuration', () => {
    it('should have correct pool settings', () => {
      const poolConfig = dataSource.options.extra;
      expect(poolConfig.max).toBe(5);
      expect(poolConfig.min).toBe(1);
      expect(poolConfig.acquire).toBe(30000);
      expect(poolConfig.idle).toBe(10000);
    });

    it('should have application name set', () => {
      expect(dataSource.options.extra.application_name).toBe('auth-service');
    });

    it('should have timeout configurations', () => {
      const config = dataSource.options.extra;
      expect(config.statement_timeout).toBe(30000);
      expect(config.query_timeout).toBe(10000);
      expect(config.connectionTimeoutMillis).toBe(5000);
    });
  });

  describe('DatabaseHealthService', () => {
    it('should be defined', () => {
      expect(healthService).toBeDefined();
    });

    it('should perform health check successfully', async () => {
      const health = await healthService.checkHealth();
      
      expect(health).toBeDefined();
      expect(health.status).toBe('healthy');
      expect(health.response_time).toBeGreaterThan(0);
      expect(health.details.can_connect).toBe(true);
      expect(health.details.can_query).toBe(true);
      expect(health.details.version).toContain('PostgreSQL');
    });

    it('should get connection pool status', async () => {
      const poolStatus = await healthService.getConnectionPoolStatus();
      
      expect(poolStatus).toBeDefined();
      expect(poolStatus.max_connections).toBe(5);
      expect(poolStatus.current_connections).toBeGreaterThan(0);
      expect(poolStatus.usage_percentage).toBeGreaterThanOrEqual(0);
      expect(poolStatus.usage_percentage).toBeLessThanOrEqual(100);
    });

    it('should get performance metrics', async () => {
      const metrics = await healthService.getPerformanceMetrics();
      
      expect(metrics).toBeDefined();
      // Metrics might be null in test environment if pg_stat_statements is not available
      expect(typeof metrics.avg_query_time === 'number' || metrics.avg_query_time === null).toBe(true);
      expect(typeof metrics.total_queries === 'number' || metrics.total_queries === null).toBe(true);
    });

    it('should log health status without errors', async () => {
      await expect(healthService.logHealthStatus()).resolves.not.toThrow();
    });
  });

  describe('DatabaseHealthController', () => {
    it('should be defined', () => {
      expect(healthController).toBeDefined();
    });

    it('should return health status', async () => {
      const health = await healthController.getHealth();
      
      expect(health).toBeDefined();
      expect(health.status).toBe('healthy');
      expect(health.response_time).toBeGreaterThan(0);
    });

    it('should return connection pool status', async () => {
      const poolStatus = await healthController.getConnectionPoolStatus();
      
      expect(poolStatus).toBeDefined();
      expect(poolStatus.max_connections).toBe(5);
      expect(poolStatus.current_connections).toBeGreaterThan(0);
    });

    it('should return performance metrics', async () => {
      const metrics = await healthController.getPerformanceMetrics();
      
      expect(metrics).toBeDefined();
      expect(typeof metrics.avg_query_time === 'number' || metrics.avg_query_time === null).toBe(true);
    });
  });

  describe('Entity Operations', () => {
    it('should create and retrieve user entity', async () => {
      const userRepository = dataSource.getRepository(UserEntity);
      
      const user = userRepository.create({
        id: 'test-user-1',
        email: 'test@example.com',
        name: 'Test User',
        provider: 'local',
        status: 'active',
      });

      const savedUser = await userRepository.save(user);
      expect(savedUser.id).toBe('test-user-1');
      expect(savedUser.email).toBe('test@example.com');

      const foundUser = await userRepository.findOne({ where: { id: 'test-user-1' } });
      expect(foundUser).toBeDefined();
      expect(foundUser?.email).toBe('test@example.com');

      // Cleanup
      await userRepository.delete({ id: 'test-user-1' });
    });

    it('should create and retrieve token entity', async () => {
      const tokenRepository = dataSource.getRepository(TokenEntity);
      
      const token = tokenRepository.create({
        id: 'test-token-1',
        user_id: 'test-user-1',
        type: 'refresh_token',
        value: 'test-token-value',
        expires_at: new Date(Date.now() + 86400000), // 1 day
      });

      const savedToken = await tokenRepository.save(token);
      expect(savedToken.id).toBe('test-token-1');
      expect(savedToken.type).toBe('refresh_token');

      const foundToken = await tokenRepository.findOne({ where: { id: 'test-token-1' } });
      expect(foundToken).toBeDefined();
      expect(foundToken?.type).toBe('refresh_token');

      // Cleanup
      await tokenRepository.delete({ id: 'test-token-1' });
    });

    it('should create and retrieve session entity', async () => {
      const sessionRepository = dataSource.getRepository(AuthSessionEntity);
      
      const session = sessionRepository.create({
        id: 'test-session-1',
        user_id: 'test-user-1',
        session_token: 'test-session-token',
        status: 'active',
        device_id: 'test-device',
        platform: 'web',
        ip_address: '127.0.0.1',
        user_agent: 'Test User Agent',
        expires_at: new Date(Date.now() + 86400000), // 1 day
      });

      const savedSession = await sessionRepository.save(session);
      expect(savedSession.id).toBe('test-session-1');
      expect(savedSession.status).toBe('active');

      const foundSession = await sessionRepository.findOne({ where: { id: 'test-session-1' } });
      expect(foundSession).toBeDefined();
      expect(foundSession?.status).toBe('active');

      // Cleanup
      await sessionRepository.delete({ id: 'test-session-1' });
    });
  });

  describe('Database Constraints', () => {
    it('should enforce unique email constraint', async () => {
      const userRepository = dataSource.getRepository(UserEntity);
      
      const user1 = userRepository.create({
        id: 'test-user-1',
        email: 'duplicate@example.com',
        name: 'User 1',
        provider: 'local',
        status: 'active',
      });

      const user2 = userRepository.create({
        id: 'test-user-2',
        email: 'duplicate@example.com',
        name: 'User 2',
        provider: 'local',
        status: 'active',
      });

      await userRepository.save(user1);
      
      await expect(userRepository.save(user2)).rejects.toThrow();

      // Cleanup
      await userRepository.delete({ id: 'test-user-1' });
    });

    it('should enforce provider check constraint', async () => {
      const userRepository = dataSource.getRepository(UserEntity);
      
      const user = userRepository.create({
        id: 'test-user-invalid',
        email: 'invalid@example.com',
        name: 'Invalid User',
        provider: 'invalid-provider' as any,
        status: 'active',
      });

      await expect(userRepository.save(user)).rejects.toThrow();
    });

    it('should enforce status check constraint', async () => {
      const userRepository = dataSource.getRepository(UserEntity);
      
      const user = userRepository.create({
        id: 'test-user-invalid-status',
        email: 'invalid-status@example.com',
        name: 'Invalid Status User',
        provider: 'local',
        status: 'invalid-status' as any,
      });

      await expect(userRepository.save(user)).rejects.toThrow();
    });
  });
});
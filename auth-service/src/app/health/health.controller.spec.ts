import { Test, TestingModule } from '@nestjs/testing';
import {
  HealthCheckService,
  TypeOrmHealthIndicator,
  MemoryHealthIndicator,
  DiskHealthIndicator,
  HealthCheckResult,
} from '@nestjs/terminus';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';

describe('HealthController', () => {
  let controller: HealthController;
  let healthCheckService: jest.Mocked<HealthCheckService>;
  let dbHealthIndicator: jest.Mocked<TypeOrmHealthIndicator>;
  let memoryHealthIndicator: jest.Mocked<MemoryHealthIndicator>;
  let diskHealthIndicator: jest.Mocked<DiskHealthIndicator>;
  let healthService: jest.Mocked<HealthService>;

  const mockHealthCheckResult: HealthCheckResult = {
    status: 'ok',
    info: {
      database: {
        status: 'up',
      },
      memory_heap: {
        status: 'up',
      },
      memory_rss: {
        status: 'up',
      },
    },
    error: {},
    details: {
      database: {
        status: 'up',
      },
      memory_heap: {
        status: 'up',
      },
      memory_rss: {
        status: 'up',
      },
    },
  };

  beforeEach(async () => {
    const mockHealthCheckService = {
      check: jest.fn(),
    };

    const mockDbHealthIndicator = {
      pingCheck: jest.fn(),
    };

    const mockMemoryHealthIndicator = {
      checkHeap: jest.fn(),
      checkRSS: jest.fn(),
    };

    const mockDiskHealthIndicator = {
      checkStorage: jest.fn(),
    };

    const mockHealthService = {
      checkJWTConfiguration: jest.fn(),
      checkOAuthConfiguration: jest.fn(),
      checkRequiredEnvironmentVariables: jest.fn(),
      checkApplicationUptime: jest.fn(),
      getApplicationInfo: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [
        {
          provide: HealthCheckService,
          useValue: mockHealthCheckService,
        },
        {
          provide: TypeOrmHealthIndicator,
          useValue: mockDbHealthIndicator,
        },
        {
          provide: MemoryHealthIndicator,
          useValue: mockMemoryHealthIndicator,
        },
        {
          provide: DiskHealthIndicator,
          useValue: mockDiskHealthIndicator,
        },
        {
          provide: HealthService,
          useValue: mockHealthService,
        },
      ],
    }).compile();

    controller = module.get<HealthController>(HealthController);
    healthCheckService = module.get(HealthCheckService);
    dbHealthIndicator = module.get(TypeOrmHealthIndicator);
    memoryHealthIndicator = module.get(MemoryHealthIndicator);
    diskHealthIndicator = module.get(DiskHealthIndicator);
    healthService = module.get(HealthService);
  });

  describe('check', () => {
    it('should perform basic health check', async () => {
      // Arrange
      healthCheckService.check.mockResolvedValue(mockHealthCheckResult);

      // Act
      const result = await controller.check();

      // Assert
      expect(healthCheckService.check).toHaveBeenCalledWith([
        expect.any(Function),
        expect.any(Function),
        expect.any(Function),
      ]);
      expect(result).toEqual(mockHealthCheckResult);
    });

    it('should call database ping check', async () => {
      // Arrange
      const mockDbCheck = jest.fn().mockResolvedValue({ database: { status: 'up' } });
      dbHealthIndicator.pingCheck.mockReturnValue(mockDbCheck as any);
      healthCheckService.check.mockImplementation(async (checks) => {
        await checks[0](); // Execute first check (database)
        return mockHealthCheckResult;
      });

      // Act
      await controller.check();

      // Assert
      expect(dbHealthIndicator.pingCheck).toHaveBeenCalledWith('database');
    });

    it('should call memory health checks', async () => {
      // Arrange
      const mockHeapCheck = jest.fn().mockResolvedValue({ memory_heap: { status: 'up' } });
      const mockRSSCheck = jest.fn().mockResolvedValue({ memory_rss: { status: 'up' } });
      memoryHealthIndicator.checkHeap.mockReturnValue(mockHeapCheck as any);
      memoryHealthIndicator.checkRSS.mockReturnValue(mockRSSCheck as any);
      
      healthCheckService.check.mockImplementation(async (checks) => {
        await checks[1](); // Execute second check (heap)
        await checks[2](); // Execute third check (RSS)
        return mockHealthCheckResult;
      });

      // Act
      await controller.check();

      // Assert
      expect(memoryHealthIndicator.checkHeap).toHaveBeenCalledWith('memory_heap', 150 * 1024 * 1024);
      expect(memoryHealthIndicator.checkRSS).toHaveBeenCalledWith('memory_rss', 300 * 1024 * 1024);
    });

    it('should handle health check failures', async () => {
      // Arrange
      const failedResult: HealthCheckResult = {
        status: 'error',
        info: {},
        error: {
          database: {
            status: 'down',
            message: 'Database connection failed',
          },
        },
        details: {
          database: {
            status: 'down',
            message: 'Database connection failed',
          },
        },
      };
      healthCheckService.check.mockResolvedValue(failedResult);

      // Act
      const result = await controller.check();

      // Assert
      expect(result.status).toBe('error');
      expect(result.error).toHaveProperty('database');
    });
  });

  describe('checkDetailed', () => {
    it('should perform detailed health check', async () => {
      // Arrange
      const detailedResult = {
        ...mockHealthCheckResult,
        details: {
          ...mockHealthCheckResult.details,
          storage: { status: 'up' },
          jwt_config: { status: 'up' },
          oauth_config: { status: 'up' },
          environment_variables: { status: 'up' },
        },
      };
      healthCheckService.check.mockResolvedValue(detailedResult);

      // Act
      const result = await controller.checkDetailed();

      // Assert
      expect(healthCheckService.check).toHaveBeenCalledWith([
        expect.any(Function), // database
        expect.any(Function), // memory heap
        expect.any(Function), // memory rss
        expect.any(Function), // disk storage
        expect.any(Function), // JWT config
        expect.any(Function), // OAuth config
        expect.any(Function), // environment variables
      ]);
      expect(result).toEqual(detailedResult);
    });

    it('should call custom health service checks', async () => {
      // Arrange
      const mockJWTCheck = jest.fn().mockResolvedValue({ jwt_config: { status: 'up' } });
      const mockOAuthCheck = jest.fn().mockResolvedValue({ oauth_config: { status: 'up' } });
      const mockEnvCheck = jest.fn().mockResolvedValue({ environment_variables: { status: 'up' } });
      
      healthService.checkJWTConfiguration.mockReturnValue(mockJWTCheck as any);
      healthService.checkOAuthConfiguration.mockReturnValue(mockOAuthCheck as any);
      healthService.checkRequiredEnvironmentVariables.mockReturnValue(mockEnvCheck as any);

      healthCheckService.check.mockImplementation(async (checks) => {
        await checks[4](); // JWT check
        await checks[5](); // OAuth check  
        await checks[6](); // Environment variables check
        return mockHealthCheckResult;
      });

      // Act
      await controller.checkDetailed();

      // Assert
      expect(healthService.checkJWTConfiguration).toHaveBeenCalled();
      expect(healthService.checkOAuthConfiguration).toHaveBeenCalled();
      expect(healthService.checkRequiredEnvironmentVariables).toHaveBeenCalled();
    });

    it('should call disk storage check', async () => {
      // Arrange
      const mockStorageCheck = jest.fn().mockResolvedValue({ storage: { status: 'up' } });
      diskHealthIndicator.checkStorage.mockReturnValue(mockStorageCheck as any);

      healthCheckService.check.mockImplementation(async (checks) => {
        await checks[3](); // Storage check
        return mockHealthCheckResult;
      });

      // Act
      await controller.checkDetailed();

      // Assert
      expect(diskHealthIndicator.checkStorage).toHaveBeenCalledWith('storage', { 
        path: '/', 
        thresholdPercent: 0.9 
      });
    });
  });

  describe('checkReadiness', () => {
    it('should perform readiness check', async () => {
      // Arrange
      healthCheckService.check.mockResolvedValue(mockHealthCheckResult);

      // Act
      const result = await controller.checkReadiness();

      // Assert
      expect(healthCheckService.check).toHaveBeenCalledWith([
        expect.any(Function), // database
        expect.any(Function), // JWT config
        expect.any(Function), // environment variables
      ]);
      expect(result).toEqual(mockHealthCheckResult);
    });

    it('should check essential services for readiness', async () => {
      // Arrange
      const mockDbCheck = jest.fn().mockResolvedValue({ database: { status: 'up' } });
      const mockJWTCheck = jest.fn().mockResolvedValue({ jwt_config: { status: 'up' } });
      const mockEnvCheck = jest.fn().mockResolvedValue({ environment_variables: { status: 'up' } });
      
      dbHealthIndicator.pingCheck.mockReturnValue(mockDbCheck as any);
      healthService.checkJWTConfiguration.mockReturnValue(mockJWTCheck as any);
      healthService.checkRequiredEnvironmentVariables.mockReturnValue(mockEnvCheck as any);

      healthCheckService.check.mockImplementation(async (checks) => {
        await checks[0](); // Database check
        await checks[1](); // JWT check
        await checks[2](); // Environment variables check
        return mockHealthCheckResult;
      });

      // Act
      await controller.checkReadiness();

      // Assert
      expect(dbHealthIndicator.pingCheck).toHaveBeenCalledWith('database');
      expect(healthService.checkJWTConfiguration).toHaveBeenCalled();
      expect(healthService.checkRequiredEnvironmentVariables).toHaveBeenCalled();
    });
  });

  describe('checkLiveness', () => {
    it('should perform liveness check', async () => {
      // Arrange
      healthCheckService.check.mockResolvedValue(mockHealthCheckResult);

      // Act
      const result = await controller.checkLiveness();

      // Assert
      expect(healthCheckService.check).toHaveBeenCalledWith([
        expect.any(Function), // memory heap
        expect.any(Function), // memory rss
        expect.any(Function), // application uptime
      ]);
      expect(result).toEqual(mockHealthCheckResult);
    });

    it('should check memory and uptime for liveness', async () => {
      // Arrange
      const mockHeapCheck = jest.fn().mockResolvedValue({ memory_heap: { status: 'up' } });
      const mockRSSCheck = jest.fn().mockResolvedValue({ memory_rss: { status: 'up' } });
      const mockUptimeCheck = jest.fn().mockResolvedValue({ application_uptime: { status: 'up' } });
      
      memoryHealthIndicator.checkHeap.mockReturnValue(mockHeapCheck as any);
      memoryHealthIndicator.checkRSS.mockReturnValue(mockRSSCheck as any);
      healthService.checkApplicationUptime.mockReturnValue(mockUptimeCheck as any);

      healthCheckService.check.mockImplementation(async (checks) => {
        await checks[0](); // Heap check
        await checks[1](); // RSS check
        await checks[2](); // Uptime check
        return mockHealthCheckResult;
      });

      // Act
      await controller.checkLiveness();

      // Assert
      expect(memoryHealthIndicator.checkHeap).toHaveBeenCalledWith('memory_heap', 500 * 1024 * 1024);
      expect(memoryHealthIndicator.checkRSS).toHaveBeenCalledWith('memory_rss', 1024 * 1024 * 1024);
      expect(healthService.checkApplicationUptime).toHaveBeenCalled();
    });
  });

  describe('getInfo', () => {
    it('should return application information', () => {
      // Arrange
      const mockAppInfo = {
        name: 'Auth Service',
        version: '1.0.0',
        environment: 'test',
        uptime: 12345,
        timestamp: '2023-12-01T10:00:00Z',
        nodeVersion: 'v18.17.0',
        platform: 'linux',
      };
      healthService.getApplicationInfo.mockReturnValue(mockAppInfo);

      // Act
      const result = controller.getInfo();

      // Assert
      expect(healthService.getApplicationInfo).toHaveBeenCalled();
      expect(result).toEqual(mockAppInfo);
    });

    it('should call health service for application info', () => {
      // Arrange
      healthService.getApplicationInfo.mockReturnValue({} as any);

      // Act
      controller.getInfo();

      // Assert
      expect(healthService.getApplicationInfo).toHaveBeenCalledTimes(1);
    });
  });

  describe('error handling', () => {
    it('should handle health check service errors', async () => {
      // Arrange
      const error = new Error('Health check service error');
      healthCheckService.check.mockRejectedValue(error);

      // Act & Assert
      await expect(controller.check()).rejects.toThrow('Health check service error');
    });

    it('should handle health service errors gracefully', async () => {
      // Arrange
      const error = new Error('Health service error');
      healthService.getApplicationInfo.mockImplementation(() => {
        throw error;
      });

      // Act & Assert
      expect(() => controller.getInfo()).toThrow('Health service error');
    });
  });
});
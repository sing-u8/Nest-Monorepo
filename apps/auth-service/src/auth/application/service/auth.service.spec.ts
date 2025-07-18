import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { AuthApplicationService } from './auth.service';
import { JwtApplicationService } from './jwt.service';
import {
  UserDomainService,
  PasswordDomainService,
  IUserRepository,
  IRefreshTokenRepository,
  USER_REPOSITORY_TOKEN,
  REFRESH_TOKEN_REPOSITORY_TOKEN,
} from '@/auth/domain';

describe('AuthApplicationService - Dependency Injection', () => {
  let service: AuthApplicationService;
  let userRepository: IUserRepository;
  let refreshTokenRepository: IRefreshTokenRepository;
  let userDomainService: UserDomainService;
  let passwordDomainService: PasswordDomainService;
  let jwtService: JwtApplicationService;
  let eventEmitter: EventEmitter2;

  beforeEach(async () => {
    // Mock 객체들 생성
    const mockUserRepository = {
      save: jest.fn(),
      findById: jest.fn(),
      findByEmail: jest.fn(),
      delete: jest.fn(),
    } as any;

    const mockRefreshTokenRepository = {
      save: jest.fn(),
      findByToken: jest.fn(),
      findActiveTokensByUserId: jest.fn(),
      deleteAllByUserId: jest.fn(),
    } as any;

    const mockUserDomainService = {
      createLocalUser: jest.fn(),
      authenticateUser: jest.fn(),
    } as any;

    const mockPasswordDomainService = {
      hashPassword: jest.fn(),
      verifyPassword: jest.fn(),
    } as any;

    const mockJwtService = {
      generateTokenPair: jest.fn(),
      verifyRefreshToken: jest.fn(),
      getRefreshTokenExpiresIn: jest.fn(),
    } as any;

    const mockEventEmitter = {
      emit: jest.fn(),
    } as any;

    const mockConfigService = {
      get: jest.fn(),
    };

    const mockNestJwtService = {
      signAsync: jest.fn(),
      verifyAsync: jest.fn(),
      decode: jest.fn(),
    };

    // 테스트 모듈 생성
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthApplicationService,
        {
          provide: USER_REPOSITORY_TOKEN,
          useValue: mockUserRepository,
        },
        {
          provide: REFRESH_TOKEN_REPOSITORY_TOKEN,
          useValue: mockRefreshTokenRepository,
        },
        {
          provide: UserDomainService,
          useValue: mockUserDomainService,
        },
        {
          provide: PasswordDomainService,
          useValue: mockPasswordDomainService,
        },
        {
          provide: JwtApplicationService,
          useValue: mockJwtService,
        },
        {
          provide: EventEmitter2,
          useValue: mockEventEmitter,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: JwtService,
          useValue: mockNestJwtService,
        },
      ],
    }).compile();

    // 서비스 및 의존성 주입된 객체들 가져오기
    service = module.get<AuthApplicationService>(AuthApplicationService);
    userRepository = module.get(USER_REPOSITORY_TOKEN);
    refreshTokenRepository = module.get(REFRESH_TOKEN_REPOSITORY_TOKEN);
    userDomainService = module.get<UserDomainService>(UserDomainService);
    passwordDomainService = module.get<PasswordDomainService>(PasswordDomainService);
    jwtService = module.get<JwtApplicationService>(JwtApplicationService);
    eventEmitter = module.get<EventEmitter2>(EventEmitter2);
  });

  describe('Dependency Injection Tests', () => {
    it('should be defined', () => {
      expect(service).toBeDefined();
    });

    it('should have userRepository injected correctly', () => {
      expect(service['userRepository']).toBeDefined();
      expect(service['userRepository']).toBe(userRepository);
    });

    it('should have refreshTokenRepository injected correctly', () => {
      expect(service['refreshTokenRepository']).toBeDefined();
      expect(service['refreshTokenRepository']).toBe(refreshTokenRepository);
    });

    it('should have userDomainService injected correctly', () => {
      expect(service['userDomainService']).toBeDefined();
      expect(service['userDomainService']).toBe(userDomainService);
    });

    it('should have passwordDomainService injected correctly', () => {
      expect(service['passwordDomainService']).toBeDefined();
      expect(service['passwordDomainService']).toBe(passwordDomainService);
    });

    it('should have jwtService injected correctly', () => {
      expect(service['jwtService']).toBeDefined();
      expect(service['jwtService']).toBe(jwtService);
    });

    it('should have eventEmitter injected correctly', () => {
      expect(service['eventEmitter']).toBeDefined();
      expect(service['eventEmitter']).toBe(eventEmitter);
    });
  });

  describe('Repository Token Injection Tests', () => {
    it('should inject USER_REPOSITORY_TOKEN correctly', () => {
      const injectedRepo = service['userRepository'];
      expect(injectedRepo).toBeDefined();
      expect(injectedRepo.save).toBeDefined();
      expect(injectedRepo.findById).toBeDefined();
      expect(injectedRepo.findByEmail).toBeDefined();
      expect(injectedRepo.delete).toBeDefined();
    });

    it('should inject REFRESH_TOKEN_REPOSITORY_TOKEN correctly', () => {
      const injectedRepo = service['refreshTokenRepository'];
      expect(injectedRepo).toBeDefined();
      expect(injectedRepo.save).toBeDefined();
      expect(injectedRepo.findByToken).toBeDefined();
      expect(injectedRepo.findActiveTokensByUserId).toBeDefined();
      expect(injectedRepo.deleteAllByUserId).toBeDefined();
    });
  });

  describe('Method Access Tests (Dependency Usage)', () => {
    it('should access userRepository methods correctly', () => {
      const repo = service['userRepository'];
      expect(repo.save).toBeDefined();
      expect(repo.findById).toBeDefined();
      expect(repo.findByEmail).toBeDefined();
      expect(repo.delete).toBeDefined();
    });

    it('should access refreshTokenRepository methods correctly', () => {
      const repo = service['refreshTokenRepository'];
      expect(repo.save).toBeDefined();
      expect(repo.findByToken).toBeDefined();
      expect(repo.findActiveTokensByUserId).toBeDefined();
      expect(repo.deleteAllByUserId).toBeDefined();
    });

    it('should access domain service methods correctly', () => {
      const userService = service['userDomainService'];
      const passwordService = service['passwordDomainService'];
      
      expect(userService.createLocalUser).toBeDefined();
      expect(userService.authenticateUser).toBeDefined();
      expect(passwordService.hashPassword).toBeDefined();
      expect(passwordService.verifyPassword).toBeDefined();
    });

    it('should access jwt service methods correctly', () => {
      const jwt = service['jwtService'];
      expect(jwt.generateTokenPair).toBeDefined();
      expect(jwt.verifyRefreshToken).toBeDefined();
      expect(jwt.getRefreshTokenExpiresIn).toBeDefined();
    });

    it('should access eventEmitter methods correctly', () => {
      const emitter = service['eventEmitter'];
      expect(emitter.emit).toBeDefined();
    });
  });

  describe('Integration Test (Constructor Injection)', () => {
    it('should create service with all dependencies properly injected', () => {
      // 모든 의존성이 정상적으로 주입되었는지 확인
      expect(service).toBeInstanceOf(AuthApplicationService);
      expect(service['userRepository']).toBeDefined();
      expect(service['refreshTokenRepository']).toBeDefined();
      expect(service['userDomainService']).toBeDefined();
      expect(service['passwordDomainService']).toBeDefined();
      expect(service['jwtService']).toBeDefined();
      expect(service['eventEmitter']).toBeDefined();
    });

    it('should have correct repository tokens injected', () => {
      // 토큰 기반 의존성 주입이 정상적으로 작동하는지 확인
      const userRepo = service['userRepository'];
      const refreshRepo = service['refreshTokenRepository'];
      
      expect(userRepo).toBeDefined();
      expect(refreshRepo).toBeDefined();
      expect(userRepo).toBe(userRepository);
      expect(refreshRepo).toBe(refreshTokenRepository);
    });
  });
});
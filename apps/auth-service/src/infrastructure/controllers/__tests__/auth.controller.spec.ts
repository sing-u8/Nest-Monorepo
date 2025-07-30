import { Test, TestingModule } from '@nestjs/testing';
import { Request } from 'express';
import { AuthController } from '../auth.controller';

// Use Cases
import { RegisterUserUseCase } from '../../../domain/use-cases/register-user.use-case';
import { LoginUserUseCase } from '../../../domain/use-cases/login-user.use-case';
import { RefreshTokenUseCase } from '../../../domain/use-cases/refresh-token.use-case';
import { LogoutUserUseCase } from '../../../domain/use-cases/logout-user.use-case';

// Presenters
import { AuthPresenter } from '../../presenters/auth.presenter';

// Entities
import { User, UserStatus, AuthProvider } from '../../../domain/entities/user.entity';
import { Token, TokenType } from '../../../domain/entities/token.entity';

describe('AuthController', () => {
  let controller: AuthController;
  let registerUserUseCase: jest.Mocked<RegisterUserUseCase>;
  let loginUserUseCase: jest.Mocked<LoginUserUseCase>;
  let refreshTokenUseCase: jest.Mocked<RefreshTokenUseCase>;
  let logoutUserUseCase: jest.Mocked<LogoutUserUseCase>;
  let authPresenter: jest.Mocked<AuthPresenter>;

  const mockUser = User.create(
    'user_123',
    'test@example.com',
    'Test User',
    'hashedPassword',
    AuthProvider.LOCAL,
    UserStatus.ACTIVE,
  );

  const mockAccessToken = Token.create(
    'token_123',
    TokenType.ACCESS,
    'access_token_value',
    new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    'user_123',
  );

  const mockRefreshToken = Token.create(
    'refresh_token_123',
    TokenType.REFRESH,
    'refresh_token_value',
    new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    'user_123',
  );

  const mockRequest = {
    headers: {
      'user-agent': 'Test-Agent/1.0',
      'x-device-id': 'device_123',
    },
    connection: {
      remoteAddress: '192.168.1.1',
    },
  } as unknown as Request;

  beforeEach(async () => {
    const mockRegisterUserUseCase = {
      execute: jest.fn(),
    };

    const mockLoginUserUseCase = {
      execute: jest.fn(),
    };

    const mockRefreshTokenUseCase = {
      execute: jest.fn(),
    };

    const mockLogoutUserUseCase = {
      execute: jest.fn(),
    };

    const mockAuthPresenter = {
      presentAuthResponse: jest.fn(),
      presentRefreshTokenResponse: jest.fn(),
      presentLogoutResponse: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: RegisterUserUseCase, useValue: mockRegisterUserUseCase },
        { provide: LoginUserUseCase, useValue: mockLoginUserUseCase },
        { provide: RefreshTokenUseCase, useValue: mockRefreshTokenUseCase },
        { provide: LogoutUserUseCase, useValue: mockLogoutUserUseCase },
        { provide: AuthPresenter, useValue: mockAuthPresenter },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    registerUserUseCase = module.get(RegisterUserUseCase);
    loginUserUseCase = module.get(LoginUserUseCase);
    refreshTokenUseCase = module.get(RefreshTokenUseCase);
    logoutUserUseCase = module.get(LogoutUserUseCase);
    authPresenter = module.get(AuthPresenter);
  });

  describe('register', () => {
    const registerDto = {
      email: 'test@example.com',
      password: 'SecurePassword123!',
      name: 'Test User',
      profilePicture: 'https://example.com/avatar.jpg',
    };

    const mockRegisterResponse = {
      user: mockUser,
      accessToken: mockAccessToken,
      refreshToken: mockRefreshToken,
      sessionId: 'session_123',
    };

    const mockPresentedResponse = {
      id: 'user_123',
      email: 'test@example.com',
      name: 'Test User',
      profilePicture: 'https://example.com/avatar.jpg',
      provider: 'LOCAL',
      accessToken: 'access_token_value',
      refreshToken: 'refresh_token_value',
      expiresAt: mockAccessToken.getExpiresAt().toISOString(),
      sessionId: 'session_123',
    };

    it('should register a new user successfully', async () => {
      // Arrange
      registerUserUseCase.execute.mockResolvedValue(mockRegisterResponse);
      authPresenter.presentAuthResponse.mockReturnValue(mockPresentedResponse);

      // Act
      const result = await controller.register(registerDto, mockRequest);

      // Assert
      expect(registerUserUseCase.execute).toHaveBeenCalledWith({
        email: registerDto.email,
        password: registerDto.password,
        name: registerDto.name,
        profilePicture: registerDto.profilePicture,
        clientInfo: {
          userAgent: 'Test-Agent/1.0',
          ipAddress: '192.168.1.1',
          deviceId: 'device_123',
        },
      });
      expect(authPresenter.presentAuthResponse).toHaveBeenCalledWith(mockRegisterResponse);
      expect(result).toEqual(mockPresentedResponse);
    });

    it('should handle registration without profile picture', async () => {
      // Arrange
      const registerDtoWithoutPicture = { ...registerDto, profilePicture: undefined };
      registerUserUseCase.execute.mockResolvedValue(mockRegisterResponse);
      authPresenter.presentAuthResponse.mockReturnValue(mockPresentedResponse);

      // Act
      const result = await controller.register(registerDtoWithoutPicture, mockRequest);

      // Assert
      expect(registerUserUseCase.execute).toHaveBeenCalledWith({
        email: registerDto.email,
        password: registerDto.password,
        name: registerDto.name,
        profilePicture: undefined,
        clientInfo: {
          userAgent: 'Test-Agent/1.0',
          ipAddress: '192.168.1.1',
          deviceId: 'device_123',
        },
      });
    });

    it('should extract client info correctly', async () => {
      // Arrange
      const requestWithoutDeviceId = {
        headers: {
          'user-agent': 'Different-Agent/2.0',
          'x-forwarded-for': '203.0.113.1, 198.51.100.1',
        },
        connection: { remoteAddress: '192.168.1.1' },
      } as unknown as Request;

      registerUserUseCase.execute.mockResolvedValue(mockRegisterResponse);
      authPresenter.presentAuthResponse.mockReturnValue(mockPresentedResponse);

      // Act
      await controller.register(registerDto, requestWithoutDeviceId);

      // Assert
      expect(registerUserUseCase.execute).toHaveBeenCalledWith({
        email: registerDto.email,
        password: registerDto.password,
        name: registerDto.name,
        profilePicture: registerDto.profilePicture,
        clientInfo: {
          userAgent: 'Different-Agent/2.0',
          ipAddress: '203.0.113.1', // First IP from x-forwarded-for
          deviceId: null,
        },
      });
    });
  });

  describe('login', () => {
    const loginDto = {
      email: 'test@example.com',
      password: 'SecurePassword123!',
    };

    const mockLoginResponse = {
      user: mockUser,
      accessToken: mockAccessToken,
      refreshToken: mockRefreshToken,
      sessionId: 'session_123',
    };

    const mockPresentedResponse = {
      id: 'user_123',
      email: 'test@example.com',
      name: 'Test User',
      profilePicture: undefined,
      provider: 'LOCAL',
      accessToken: 'access_token_value',
      refreshToken: 'refresh_token_value',
      expiresAt: mockAccessToken.getExpiresAt().toISOString(),
      sessionId: 'session_123',
    };

    it('should login user successfully', async () => {
      // Arrange
      loginUserUseCase.execute.mockResolvedValue(mockLoginResponse);
      authPresenter.presentAuthResponse.mockReturnValue(mockPresentedResponse);

      // Act
      const result = await controller.login(loginDto, mockRequest);

      // Assert
      expect(loginUserUseCase.execute).toHaveBeenCalledWith({
        email: loginDto.email,
        password: loginDto.password,
        clientInfo: {
          userAgent: 'Test-Agent/1.0',
          ipAddress: '192.168.1.1',
          deviceId: 'device_123',
        },
      });
      expect(authPresenter.presentAuthResponse).toHaveBeenCalledWith(mockLoginResponse);
      expect(result).toEqual(mockPresentedResponse);
    });

    it('should handle login with missing user agent', async () => {
      // Arrange
      const requestWithoutUserAgent = {
        headers: {},
        connection: { remoteAddress: '192.168.1.1' },
      } as unknown as Request;

      loginUserUseCase.execute.mockResolvedValue(mockLoginResponse);
      authPresenter.presentAuthResponse.mockReturnValue(mockPresentedResponse);

      // Act
      await controller.login(loginDto, requestWithoutUserAgent);

      // Assert
      expect(loginUserUseCase.execute).toHaveBeenCalledWith({
        email: loginDto.email,
        password: loginDto.password,
        clientInfo: {
          userAgent: 'Unknown',
          ipAddress: '192.168.1.1',
          deviceId: null,
        },
      });
    });
  });

  describe('refreshToken', () => {
    const refreshDto = {
      refreshToken: 'refresh_token_value',
    };

    const mockRefreshResponse = {
      accessToken: mockAccessToken,
      refreshToken: mockRefreshToken,
      sessionId: 'session_123',
    };

    const mockPresentedResponse = {
      accessToken: 'access_token_value',
      refreshToken: 'refresh_token_value',
      expiresAt: mockAccessToken.getExpiresAt().toISOString(),
      sessionId: 'session_123',
    };

    it('should refresh token successfully', async () => {
      // Arrange
      refreshTokenUseCase.execute.mockResolvedValue(mockRefreshResponse);
      authPresenter.presentRefreshTokenResponse.mockReturnValue(mockPresentedResponse);

      // Act
      const result = await controller.refreshToken(refreshDto, mockRequest);

      // Assert
      expect(refreshTokenUseCase.execute).toHaveBeenCalledWith({
        refreshToken: refreshDto.refreshToken,
        clientInfo: {
          userAgent: 'Test-Agent/1.0',
          ipAddress: '192.168.1.1',
          deviceId: 'device_123',
        },
      });
      expect(authPresenter.presentRefreshTokenResponse).toHaveBeenCalledWith(mockRefreshResponse);
      expect(result).toEqual(mockPresentedResponse);
    });
  });

  describe('logout', () => {
    const mockLogoutResponse = {
      message: 'Successfully logged out',
      timestamp: new Date(),
    };

    const mockPresentedResponse = {
      message: 'Successfully logged out',
      timestamp: mockLogoutResponse.timestamp.toISOString(),
    };

    it('should logout user successfully', async () => {
      // Arrange
      const requestWithUser = {
        ...mockRequest,
        user: {
          userId: 'user_123',
          sessionId: 'session_123',
        },
      } as unknown as Request;

      logoutUserUseCase.execute.mockResolvedValue(mockLogoutResponse);
      authPresenter.presentLogoutResponse.mockReturnValue(mockPresentedResponse);

      // Act
      const result = await controller.logout(requestWithUser);

      // Assert
      expect(logoutUserUseCase.execute).toHaveBeenCalledWith({
        userId: 'user_123',
        sessionId: 'session_123',
      });
      expect(authPresenter.presentLogoutResponse).toHaveBeenCalledWith(mockLogoutResponse);
      expect(result).toEqual(mockPresentedResponse);
    });

    it('should handle logout with temporary user data', async () => {
      // Arrange
      logoutUserUseCase.execute.mockResolvedValue(mockLogoutResponse);
      authPresenter.presentLogoutResponse.mockReturnValue(mockPresentedResponse);

      // Act
      const result = await controller.logout(mockRequest);

      // Assert
      expect(logoutUserUseCase.execute).toHaveBeenCalledWith({
        userId: 'temp_user_id',
        sessionId: 'temp_session_id',
      });
    });
  });

  describe('getCurrentUser', () => {
    it('should return placeholder response', async () => {
      // Arrange
      const requestWithUser = {
        ...mockRequest,
        user: {
          userId: 'user_123',
        },
      } as unknown as Request;

      // Act
      const result = await controller.getCurrentUser(requestWithUser);

      // Assert
      expect(result).toEqual({
        message: 'Get current user endpoint - to be implemented with JWT guard',
        userId: 'user_123',
        timestamp: expect.any(String),
      });
    });

    it('should handle request without user', async () => {
      // Act
      const result = await controller.getCurrentUser(mockRequest);

      // Assert
      expect(result).toEqual({
        message: 'Get current user endpoint - to be implemented with JWT guard',
        userId: 'temp_user_id',
        timestamp: expect.any(String),
      });
    });
  });

  describe('client info extraction', () => {
    it('should extract IP from x-real-ip header', async () => {
      // Arrange
      const requestWithRealIp = {
        headers: {
          'user-agent': 'Test-Agent/1.0',
          'x-real-ip': '203.0.113.1',
        },
        connection: { remoteAddress: '192.168.1.1' },
      } as unknown as Request;

      const registerDto = {
        email: 'test@example.com',
        password: 'SecurePassword123!',
        name: 'Test User',
      };

      registerUserUseCase.execute.mockResolvedValue({
        user: mockUser,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        sessionId: 'session_123',
      });

      // Act
      await controller.register(registerDto, requestWithRealIp);

      // Assert
      expect(registerUserUseCase.execute).toHaveBeenCalledWith(
        expect.objectContaining({
          clientInfo: expect.objectContaining({
            ipAddress: '203.0.113.1',
          }),
        }),
      );
    });

    it('should fallback to connection.remoteAddress when no proxy headers', async () => {
      // Arrange
      const requestWithoutProxyHeaders = {
        headers: {
          'user-agent': 'Test-Agent/1.0',
        },
        connection: { remoteAddress: '192.168.1.1' },
        socket: { remoteAddress: '10.0.0.1' },
      } as unknown as Request;

      const registerDto = {
        email: 'test@example.com',
        password: 'SecurePassword123!',
        name: 'Test User',
      };

      registerUserUseCase.execute.mockResolvedValue({
        user: mockUser,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        sessionId: 'session_123',
      });

      // Act
      await controller.register(registerDto, requestWithoutProxyHeaders);

      // Assert
      expect(registerUserUseCase.execute).toHaveBeenCalledWith(
        expect.objectContaining({
          clientInfo: expect.objectContaining({
            ipAddress: '192.168.1.1',
          }),
        }),
      );
    });

    it('should return Unknown when no IP address available', async () => {
      // Arrange
      const requestWithoutIp = {
        headers: {
          'user-agent': 'Test-Agent/1.0',
        },
        connection: {},
        socket: {},
      } as unknown as Request;

      const registerDto = {
        email: 'test@example.com',
        password: 'SecurePassword123!',
        name: 'Test User',
      };

      registerUserUseCase.execute.mockResolvedValue({
        user: mockUser,
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
        sessionId: 'session_123',
      });

      // Act
      await controller.register(registerDto, requestWithoutIp);

      // Assert
      expect(registerUserUseCase.execute).toHaveBeenCalledWith(
        expect.objectContaining({
          clientInfo: expect.objectContaining({
            ipAddress: 'Unknown',
          }),
        }),
      );
    });
  });
});
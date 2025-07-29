import { GetUserProfileUseCase } from './get-user-profile.use-case';
import { UserRepository } from '../ports/repositories/user.repository';
import { AuthSessionRepository } from '../ports/repositories/auth-session.repository';
import { User } from '../entities/user.entity';
import { AuthSession } from '../entities/auth-session.entity';
import { GetUserProfileRequest } from '@auth/shared';
import { AuthProvider } from '@auth/shared';

describe('GetUserProfileUseCase', () => {
  let useCase: GetUserProfileUseCase;
  let userRepository: jest.Mocked<UserRepository>;
  let sessionRepository: jest.Mocked<AuthSessionRepository>;

  const mockUser = User.create({
    id: 'user-123',
    email: 'test@example.com',
    password: 'hashed-password',
    name: 'Test User',
    profilePicture: 'https://example.com/profile.jpg',
    provider: AuthProvider.LOCAL,
  });

  const mockSession = AuthSession.create({
    id: 'session-123',
    userId: 'user-123',
    sessionToken: 'session-token-value',
    clientInfo: {
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
    },
    expirationHours: 24,
  });

  beforeEach(() => {
    userRepository = {
      findByEmail: jest.fn(),
      findById: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      findAll: jest.fn(),
    };

    sessionRepository = {
      findByUserId: jest.fn(),
      findBySessionToken: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      deleteByUserId: jest.fn(),
      deleteExpiredSessions: jest.fn(),
    };

    useCase = new GetUserProfileUseCase(
      userRepository,
      sessionRepository
    );
  });

  describe('execute', () => {
    const validRequest: GetUserProfileRequest = {
      userId: 'user-123',
      sessionToken: 'session-token-value',
    };

    it('should successfully retrieve user profile', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(mockUser);
      sessionRepository.findBySessionToken.mockResolvedValue(mockSession);

      // Act
      const result = await useCase.execute(validRequest);

      // Assert
      expect(userRepository.findById).toHaveBeenCalledWith('user-123');
      expect(sessionRepository.findBySessionToken).toHaveBeenCalledWith('session-token-value');
      expect(result).toEqual({
        user: {
          id: 'user-123',
          email: 'test@example.com',
          name: 'Test User',
          profilePicture: 'https://example.com/profile.jpg',
          provider: AuthProvider.LOCAL,
          createdAt: expect.any(Date),
          updatedAt: expect.any(Date),
        },
        session: {
          id: 'session-123',
          createdAt: expect.any(Date),
          expiresAt: expect.any(Date),
          clientInfo: {
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
          },
        },
      });
    });

    it('should throw error when user not found', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(null);
      sessionRepository.findBySessionToken.mockResolvedValue(mockSession);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('User not found');
      expect(userRepository.findById).toHaveBeenCalledWith('user-123');
    });

    it('should throw error when session not found', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(mockUser);
      sessionRepository.findBySessionToken.mockResolvedValue(null);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Session not found');
      expect(sessionRepository.findBySessionToken).toHaveBeenCalledWith('session-token-value');
    });

    it('should throw error when session does not belong to user', async () => {
      // Arrange
      const sessionForDifferentUser = AuthSession.create({
        id: 'session-456',
        userId: 'different-user-456',
        sessionToken: 'session-token-value',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'test-agent',
        },
        expirationHours: 24,
      });

      userRepository.findById.mockResolvedValue(mockUser);
      sessionRepository.findBySessionToken.mockResolvedValue(sessionForDifferentUser);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Session does not belong to user');
    });

    it('should throw error when session is expired', async () => {
      // Arrange
      const expiredSession = AuthSession.create({
        id: 'session-123',
        userId: 'user-123',
        sessionToken: 'session-token-value',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'test-agent',
        },
        expirationHours: -1, // Expired 1 hour ago
      });

      userRepository.findById.mockResolvedValue(mockUser);
      sessionRepository.findBySessionToken.mockResolvedValue(expiredSession);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Session has expired');
    });

    it('should validate required fields', async () => {
      // Arrange & Act & Assert
      await expect(useCase.execute({ userId: '', sessionToken: 'token' }))
        .rejects.toThrow('User ID is required');

      await expect(useCase.execute({ userId: 'user-123', sessionToken: '' }))
        .rejects.toThrow('Session token is required');

      await expect(useCase.execute({ userId: null as any, sessionToken: 'token' }))
        .rejects.toThrow('User ID is required');

      await expect(useCase.execute({ userId: 'user-123', sessionToken: null as any }))
        .rejects.toThrow('Session token is required');
    });

    it('should handle database errors gracefully', async () => {
      // Arrange
      userRepository.findById.mockRejectedValue(new Error('Database connection failed'));

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Database connection failed');
    });

    it('should handle session repository errors gracefully', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(mockUser);
      sessionRepository.findBySessionToken.mockRejectedValue(new Error('Session database error'));

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Session database error');
    });

    it('should return user profile without sensitive information', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(mockUser);
      sessionRepository.findBySessionToken.mockResolvedValue(mockSession);

      // Act
      const result = await useCase.execute(validRequest);

      // Assert
      expect(result.user).not.toHaveProperty('password');
      expect(result.user).toHaveProperty('id');
      expect(result.user).toHaveProperty('email');
      expect(result.user).toHaveProperty('name');
      expect(result.user).toHaveProperty('profilePicture');
      expect(result.user).toHaveProperty('provider');
      expect(result.user).toHaveProperty('createdAt');
      expect(result.user).toHaveProperty('updatedAt');
    });

    it('should return session information without sensitive data', async () => {
      // Arrange
      userRepository.findById.mockResolvedValue(mockUser);
      sessionRepository.findBySessionToken.mockResolvedValue(mockSession);

      // Act
      const result = await useCase.execute(validRequest);

      // Assert
      expect(result.session).not.toHaveProperty('sessionToken');
      expect(result.session).toHaveProperty('id');
      expect(result.session).toHaveProperty('createdAt');
      expect(result.session).toHaveProperty('expiresAt');
      expect(result.session).toHaveProperty('clientInfo');
    });

    it('should handle user with minimal profile information', async () => {
      // Arrange
      const minimalUser = User.create({
        id: 'user-123',
        email: 'test@example.com',
        password: 'hashed-password',
        name: 'Test User',
        provider: AuthProvider.LOCAL,
      });

      userRepository.findById.mockResolvedValue(minimalUser);
      sessionRepository.findBySessionToken.mockResolvedValue(mockSession);

      // Act
      const result = await useCase.execute(validRequest);

      // Assert
      expect(result.user).toEqual({
        id: 'user-123',
        email: 'test@example.com',
        name: 'Test User',
        profilePicture: undefined,
        provider: AuthProvider.LOCAL,
        createdAt: expect.any(Date),
        updatedAt: expect.any(Date),
      });
    });

    it('should handle social login user profiles', async () => {
      // Arrange
      const socialUser = User.create({
        id: 'user-123',
        email: 'test@example.com',
        password: null, // Social users might not have passwords
        name: 'Test User',
        profilePicture: 'https://googleusercontent.com/profile.jpg',
        provider: AuthProvider.GOOGLE,
      });

      userRepository.findById.mockResolvedValue(socialUser);
      sessionRepository.findBySessionToken.mockResolvedValue(mockSession);

      // Act
      const result = await useCase.execute(validRequest);

      // Assert
      expect(result.user.provider).toBe(AuthProvider.GOOGLE);
      expect(result.user.profilePicture).toBe('https://googleusercontent.com/profile.jpg');
      expect(result.user).not.toHaveProperty('password');
    });
  });

  describe('session validation', () => {
    const validRequest: GetUserProfileRequest = {
      userId: 'user-123',
      sessionToken: 'session-token-value',
    };

    it('should validate session expiration correctly', async () => {
      // Arrange
      const futureSession = AuthSession.create({
        id: 'session-123',
        userId: 'user-123',
        sessionToken: 'session-token-value',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'test-agent',
        },
        expirationHours: 24, // Expires in 24 hours
      });

      userRepository.findById.mockResolvedValue(mockUser);
      sessionRepository.findBySessionToken.mockResolvedValue(futureSession);

      // Act
      const result = await useCase.execute(validRequest);

      // Assert
      expect(result).toBeDefined();
      expect(result.user.id).toBe('user-123');
    });

    it('should reject recently expired sessions', async () => {
      // Arrange
      const recentlyExpiredSession = AuthSession.create({
        id: 'session-123',
        userId: 'user-123',
        sessionToken: 'session-token-value',
        clientInfo: {
          ipAddress: '127.0.0.1',
          userAgent: 'test-agent',
        },
        expirationHours: -0.1, // Expired 6 minutes ago
      });

      userRepository.findById.mockResolvedValue(mockUser);
      sessionRepository.findBySessionToken.mockResolvedValue(recentlyExpiredSession);

      // Act & Assert
      await expect(useCase.execute(validRequest)).rejects.toThrow('Session has expired');
    });
  });
});
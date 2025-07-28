import { Test, TestingModule } from '@nestjs/testing';
import * as bcrypt from 'bcrypt';
import { BcryptPasswordHashingService } from './bcrypt-password-hashing.service';

// Mock bcrypt
jest.mock('bcrypt');
const mockedBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

describe('BcryptPasswordHashingService', () => {
  let service: BcryptPasswordHashingService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [BcryptPasswordHashingService],
    }).compile();

    service = module.get<BcryptPasswordHashingService>(BcryptPasswordHashingService);
    
    // Reset all mocks
    jest.clearAllMocks();
  });

  describe('hash', () => {
    it('should hash password with default salt rounds', async () => {
      const plainPassword = 'testPassword123!';
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.hash.mockResolvedValue(hashedPassword);

      const result = await service.hash(plainPassword);

      expect(mockedBcrypt.hash).toHaveBeenCalledWith(plainPassword, 12);
      expect(result).toBe(hashedPassword);
    });

    it('should hash password with custom salt rounds', async () => {
      const plainPassword = 'testPassword123!';
      const saltRounds = 14;
      const hashedPassword = '$2b$14$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.hash.mockResolvedValue(hashedPassword);

      const result = await service.hash(plainPassword, saltRounds);

      expect(mockedBcrypt.hash).toHaveBeenCalledWith(plainPassword, saltRounds);
      expect(result).toBe(hashedPassword);
    });

    it('should throw error for empty password', async () => {
      await expect(service.hash('')).rejects.toThrow('Password cannot be empty');
    });

    it('should throw error for undefined password', async () => {
      await expect(service.hash(undefined as any)).rejects.toThrow('Password is required');
    });

    it('should throw error for non-string password', async () => {
      await expect(service.hash(123 as any)).rejects.toThrow('Password must be a string');
    });

    it('should throw error for password exceeding 128 characters', async () => {
      const longPassword = 'a'.repeat(129);
      await expect(service.hash(longPassword)).rejects.toThrow('Password length cannot exceed 128 characters');
    });

    it('should throw error for salt rounds below minimum', async () => {
      await expect(service.hash('password', 9)).rejects.toThrow('Salt rounds must be at least 10 for security');
    });

    it('should throw error for salt rounds above maximum', async () => {
      await expect(service.hash('password', 17)).rejects.toThrow('Salt rounds cannot exceed 16 for performance');
    });

    it('should throw error for non-integer salt rounds', async () => {
      await expect(service.hash('password', 12.5)).rejects.toThrow('Salt rounds must be a positive integer');
    });

    it('should handle bcrypt errors gracefully', async () => {
      mockedBcrypt.hash.mockRejectedValue(new Error('Bcrypt error'));

      await expect(service.hash('password')).rejects.toThrow('Failed to hash password');
    });
  });

  describe('compare', () => {
    it('should return true for matching passwords', async () => {
      const plainPassword = 'testPassword123!';
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.compare.mockResolvedValue(true);

      const result = await service.compare(plainPassword, hashedPassword);

      expect(mockedBcrypt.compare).toHaveBeenCalledWith(plainPassword, hashedPassword);
      expect(result).toBe(true);
    });

    it('should return false for non-matching passwords', async () => {
      const plainPassword = 'testPassword123!';
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.compare.mockResolvedValue(false);

      const result = await service.compare(plainPassword, hashedPassword);

      expect(result).toBe(false);
    });

    it('should return false for invalid plain password', async () => {
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';

      const result = await service.compare('', hashedPassword);

      expect(result).toBe(false);
      expect(mockedBcrypt.compare).not.toHaveBeenCalled();
    });

    it('should return false for invalid hashed password', async () => {
      const plainPassword = 'testPassword123!';

      const result = await service.compare(plainPassword, 'invalid-hash');

      expect(result).toBe(false);
      expect(mockedBcrypt.compare).not.toHaveBeenCalled();
    });

    it('should return false when bcrypt compare throws error', async () => {
      const plainPassword = 'testPassword123!';
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.compare.mockRejectedValue(new Error('Bcrypt error'));

      const result = await service.compare(plainPassword, hashedPassword);

      expect(result).toBe(false);
    });
  });

  describe('generateSalt', () => {
    it('should generate salt with default rounds', async () => {
      const mockSalt = '$2b$12$LQv3c1yqBWVHxkd0LHAkCO';
      mockedBcrypt.genSalt.mockResolvedValue(mockSalt);

      const result = await service.generateSalt();

      expect(mockedBcrypt.genSalt).toHaveBeenCalledWith(12);
      expect(result).toBe(mockSalt);
    });

    it('should generate salt with custom rounds', async () => {
      const mockSalt = '$2b$14$LQv3c1yqBWVHxkd0LHAkCO';
      const customRounds = 14;
      mockedBcrypt.genSalt.mockResolvedValue(mockSalt);

      const result = await service.generateSalt(customRounds);

      expect(mockedBcrypt.genSalt).toHaveBeenCalledWith(customRounds);
      expect(result).toBe(mockSalt);
    });

    it('should throw error for invalid salt rounds', async () => {
      await expect(service.generateSalt(9)).rejects.toThrow('Salt rounds must be at least 10 for security');
    });

    it('should handle bcrypt genSalt errors', async () => {
      mockedBcrypt.genSalt.mockRejectedValue(new Error('Bcrypt error'));

      await expect(service.generateSalt()).rejects.toThrow('Failed to generate salt');
    });
  });

  describe('hashWithSalt', () => {
    it('should hash password with provided salt', async () => {
      const plainPassword = 'testPassword123!';
      const salt = '$2b$12$LQv3c1yqBWVHxkd0LHAkCO';
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.hash.mockResolvedValue(hashedPassword);

      const result = await service.hashWithSalt(plainPassword, salt);

      expect(mockedBcrypt.hash).toHaveBeenCalledWith(plainPassword, salt);
      expect(result).toBe(hashedPassword);
    });

    it('should throw error for invalid password', async () => {
      const salt = '$2b$12$LQv3c1yqBWVHxkd0LHAkCO';

      await expect(service.hashWithSalt('', salt)).rejects.toThrow('Password cannot be empty');
    });

    it('should throw error for invalid salt format', async () => {
      const plainPassword = 'testPassword123!';
      const invalidSalt = 'invalid-salt';

      await expect(service.hashWithSalt(plainPassword, invalidSalt)).rejects.toThrow('Invalid bcrypt salt format');
    });

    it('should handle bcrypt errors', async () => {
      const plainPassword = 'testPassword123!';
      const salt = '$2b$12$LQv3c1yqBWVHxkd0LHAkCO';
      
      mockedBcrypt.hash.mockRejectedValue(new Error('Bcrypt error'));

      await expect(service.hashWithSalt(plainPassword, salt)).rejects.toThrow('Failed to hash password with salt');
    });
  });

  describe('getRounds', () => {
    it('should get rounds from bcrypt hash', () => {
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      const rounds = 12;
      
      mockedBcrypt.getRounds.mockReturnValue(rounds);

      const result = service.getRounds(hashedPassword);

      expect(mockedBcrypt.getRounds).toHaveBeenCalledWith(hashedPassword);
      expect(result).toBe(rounds);
    });

    it('should throw error for invalid hash format', () => {
      const invalidHash = 'invalid-hash';

      expect(() => service.getRounds(invalidHash)).toThrow('Invalid bcrypt hash format');
    });

    it('should handle bcrypt getRounds errors', () => {
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.getRounds.mockImplementation(() => {
        throw new Error('Bcrypt error');
      });

      expect(() => service.getRounds(hashedPassword)).toThrow('Failed to get rounds from hashed password');
    });
  });

  describe('needsRehash', () => {
    it('should return true when current rounds are higher than existing rounds', () => {
      const hashedPassword = '$2b$10$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      const currentRounds = 12;
      
      mockedBcrypt.getRounds.mockReturnValue(10);

      const result = service.needsRehash(hashedPassword, currentRounds);

      expect(result).toBe(true);
    });

    it('should return false when current rounds are equal to existing rounds', () => {
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      const currentRounds = 12;
      
      mockedBcrypt.getRounds.mockReturnValue(12);

      const result = service.needsRehash(hashedPassword, currentRounds);

      expect(result).toBe(false);
    });

    it('should return false when current rounds are lower than existing rounds', () => {
      const hashedPassword = '$2b$14$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      const currentRounds = 12;
      
      mockedBcrypt.getRounds.mockReturnValue(14);

      const result = service.needsRehash(hashedPassword, currentRounds);

      expect(result).toBe(false);
    });

    it('should return true on error for security', () => {
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      const currentRounds = 12;
      
      mockedBcrypt.getRounds.mockImplementation(() => {
        throw new Error('Bcrypt error');
      });

      const result = service.needsRehash(hashedPassword, currentRounds);

      expect(result).toBe(true);
    });

    it('should throw error for invalid current rounds', () => {
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';

      expect(() => service.needsRehash(hashedPassword, 9)).toThrow('Salt rounds must be at least 10 for security');
    });
  });

  describe('getRecommendedRounds', () => {
    it('should return default recommended rounds', () => {
      const result = service.getRecommendedRounds();

      expect(result).toBe(12);
    });
  });

  describe('healthCheck', () => {
    it('should return true when service is healthy', async () => {
      const testHash = '$2b$10$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.hash.mockResolvedValue(testHash);
      mockedBcrypt.compare.mockResolvedValue(true);

      const result = await service.healthCheck();

      expect(result).toBe(true);
      expect(mockedBcrypt.hash).toHaveBeenCalledWith('health-check-test', 10);
      expect(mockedBcrypt.compare).toHaveBeenCalledWith('health-check-test', testHash);
    });

    it('should return false when hash fails', async () => {
      mockedBcrypt.hash.mockRejectedValue(new Error('Hash error'));

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });

    it('should return false when compare fails', async () => {
      const testHash = '$2b$10$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.hash.mockResolvedValue(testHash);
      mockedBcrypt.compare.mockRejectedValue(new Error('Compare error'));

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });

    it('should return false when comparison returns false', async () => {
      const testHash = '$2b$10$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.hash.mockResolvedValue(testHash);
      mockedBcrypt.compare.mockResolvedValue(false);

      const result = await service.healthCheck();

      expect(result).toBe(false);
    });
  });

  describe('getConfiguration', () => {
    it('should return service configuration', () => {
      const result = service.getConfiguration();

      expect(result).toEqual({
        defaultRounds: 12,
        minRounds: 10,
        maxRounds: 16,
        algorithm: 'bcrypt',
      });
    });
  });

  describe('validation methods', () => {
    it('should accept valid bcrypt hash format - $2a$', () => {
      const validHash = '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.getRounds.mockReturnValue(12);
      
      expect(() => service.getRounds(validHash)).not.toThrow();
    });

    it('should accept valid bcrypt hash format - $2b$', () => {
      const validHash = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.getRounds.mockReturnValue(12);
      
      expect(() => service.getRounds(validHash)).not.toThrow();
    });

    it('should accept valid bcrypt hash format - $2y$', () => {
      const validHash = '$2y$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.getRounds.mockReturnValue(12);
      
      expect(() => service.getRounds(validHash)).not.toThrow();
    });

    it('should accept valid bcrypt salt format', async () => {
      const validSalt = '$2b$12$LQv3c1yqBWVHxkd0LHAkCO';
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.hash.mockResolvedValue(hashedPassword);

      await expect(service.hashWithSalt('password', validSalt)).resolves.toBeDefined();
    });

    it('should accept password with exactly 128 characters', async () => {
      const maxLengthPassword = 'a'.repeat(128);
      const hashedPassword = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeR.g0.jqJo7v2fSG';
      
      mockedBcrypt.hash.mockResolvedValue(hashedPassword);

      await expect(service.hash(maxLengthPassword)).resolves.toBeDefined();
    });
  });
});
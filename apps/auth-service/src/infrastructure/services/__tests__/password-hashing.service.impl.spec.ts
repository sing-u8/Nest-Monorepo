import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { PasswordHashingServiceImpl } from '../password-hashing.service.impl';

describe('PasswordHashingServiceImpl', () => {
  let service: PasswordHashingServiceImpl;
  let configService: jest.Mocked<ConfigService>;

  beforeEach(async () => {
    const mockConfigService = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PasswordHashingServiceImpl,
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<PasswordHashingServiceImpl>(PasswordHashingServiceImpl);
    configService = module.get(ConfigService);

    // Mock default salt rounds
    configService.get.mockReturnValue(12);
  });

  describe('hash', () => {
    it('should hash a valid password', async () => {
      // Arrange
      const password = 'TestPassword123!';

      // Act
      const hashedPassword = await service.hash(password);

      // Assert
      expect(hashedPassword).toBeDefined();
      expect(hashedPassword).not.toBe(password);
      expect(hashedPassword).toMatch(/^\$2[abyxz]\$\d{2}\$.{53}$/); // bcrypt format
    });

    it('should generate different hashes for the same password', async () => {
      // Arrange
      const password = 'TestPassword123!';

      // Act
      const hash1 = await service.hash(password);
      const hash2 = await service.hash(password);

      // Assert
      expect(hash1).not.toBe(hash2);
    });

    it('should throw error for invalid password format', async () => {
      // Arrange
      const invalidPassword = 'weak'; // Too short, no uppercase, no special chars

      // Act & Assert
      await expect(service.hash(invalidPassword)).rejects.toThrow('Password does not meet security requirements');
    });

    it('should throw error for empty password', async () => {
      // Arrange
      const emptyPassword = '';

      // Act & Assert
      await expect(service.hash(emptyPassword)).rejects.toThrow('Password must be a non-empty string');
    });

    it('should throw error for non-string password', async () => {
      // Arrange
      const nonStringPassword = 123 as any;

      // Act & Assert
      await expect(service.hash(nonStringPassword)).rejects.toThrow('Password must be a non-empty string');
    });
  });

  describe('compare', () => {
    it('should return true for correct password', async () => {
      // Arrange
      const password = 'TestPassword123!';
      const hashedPassword = await service.hash(password);

      // Act
      const result = await service.compare(password, hashedPassword);

      // Assert
      expect(result).toBe(true);
    });

    it('should return false for incorrect password', async () => {
      // Arrange
      const correctPassword = 'TestPassword123!';
      const incorrectPassword = 'WrongPassword123!';
      const hashedPassword = await service.hash(correctPassword);

      // Act
      const result = await service.compare(incorrectPassword, hashedPassword);

      // Assert
      expect(result).toBe(false);
    });

    it('should return false for empty password', async () => {
      // Arrange
      const hashedPassword = '$2b$12$test.hash.string';

      // Act
      const result = await service.compare('', hashedPassword);

      // Assert
      expect(result).toBe(false);
    });

    it('should return false for empty hash', async () => {
      // Arrange
      const password = 'TestPassword123!';

      // Act
      const result = await service.compare(password, '');

      // Assert
      expect(result).toBe(false);
    });

    it('should return false for non-string inputs', async () => {
      // Act & Assert
      expect(await service.compare(123 as any, 'hash')).toBe(false);
      expect(await service.compare('password', 123 as any)).toBe(false);
    });

    it('should handle bcrypt errors gracefully', async () => {
      // Arrange
      const password = 'TestPassword123!';
      const invalidHash = 'invalid.hash.format';

      // Act
      const result = await service.compare(password, invalidHash);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('isValidPasswordFormat', () => {
    it('should return true for valid passwords', async () => {
      // Arrange
      const validPasswords = [
        'TestPassword123!',
        'MySecure@Pass1',
        'StrongP@ssw0rd',
        'Complex#Password2023',
      ];

      // Act & Assert
      validPasswords.forEach(password => {
        expect(service.isValidPasswordFormat(password)).toBe(true);
      });
    });

    it('should return false for invalid passwords', async () => {
      // Arrange
      const invalidPasswords = [
        '', // Empty
        'short', // Too short
        'nouppercase123!', // No uppercase
        'NOLOWERCASE123!', // No lowercase
        'NoNumbers!', // No numbers
        'NoSpecialChars123', // No special characters
        'a'.repeat(129), // Too long
      ];

      // Act & Assert
      invalidPasswords.forEach(password => {
        expect(service.isValidPasswordFormat(password)).toBe(false);
      });
    });

    it('should return false for non-string input', async () => {
      // Act & Assert
      expect(service.isValidPasswordFormat(null as any)).toBe(false);
      expect(service.isValidPasswordFormat(undefined as any)).toBe(false);
      expect(service.isValidPasswordFormat(123 as any)).toBe(false);
    });
  });

  describe('generateSalt', () => {
    it('should generate a valid salt with default rounds', async () => {
      // Act
      const salt = await service.generateSalt();

      // Assert
      expect(salt).toBeDefined();
      expect(salt).toMatch(/^\$2[abyxz]\$12\$/); // Salt with 12 rounds
    });

    it('should generate a valid salt with custom rounds', async () => {
      // Act
      const salt = await service.generateSalt(10);

      // Assert
      expect(salt).toBeDefined();
      expect(salt).toMatch(/^\$2[abyxz]\$10\$/); // Salt with 10 rounds
    });

    it('should throw error for invalid salt rounds', async () => {
      // Act & Assert
      await expect(service.generateSalt(5)).rejects.toThrow('Salt rounds must be between 10 and 15');
      await expect(service.generateSalt(20)).rejects.toThrow('Salt rounds must be between 10 and 15');
    });
  });

  describe('validateHashedPassword', () => {
    it('should return true for valid bcrypt hash', async () => {
      // Arrange
      const validHash = '$2b$12$R9h/cIPz0gi.URNNX3kh2ORAN4QcxlK2PqVWfA6pLy5g5gN5GU2oK';

      // Act
      const result = service.validateHashedPassword(validHash);

      // Assert
      expect(result).toBe(true);
    });

    it('should return false for invalid hash format', async () => {
      // Arrange
      const invalidHashes = [
        '',
        'invalid.hash',
        '$2b$12$tooshort',
        '$3b$12$R9h/cIPz0gi.URNNX3kh2ORAN4QcxlK2PqVWfA6pLy5g5gN5GU2oK', // Invalid version
      ];

      // Act & Assert
      invalidHashes.forEach(hash => {
        expect(service.validateHashedPassword(hash)).toBe(false);
      });
    });

    it('should return false for non-string input', async () => {
      // Act & Assert
      expect(service.validateHashedPassword(null as any)).toBe(false);
      expect(service.validateHashedPassword(undefined as any)).toBe(false);
      expect(service.validateHashedPassword(123 as any)).toBe(false);
    });
  });

  describe('getPasswordRequirements', () => {
    it('should return password requirements string', async () => {
      // Act
      const requirements = service.getPasswordRequirements();

      // Assert
      expect(requirements).toBe('Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character');
    });
  });

  describe('getSaltRounds', () => {
    it('should return configured salt rounds', async () => {
      // Act
      const saltRounds = service.getSaltRounds();

      // Assert
      expect(saltRounds).toBe(12);
    });
  });

  describe('rehashIfNeeded', () => {
    it('should return null if rehashing is not needed', async () => {
      // Arrange
      const password = 'TestPassword123!';
      const currentHash = await service.hash(password); // Uses default 12 rounds

      // Act
      const result = await service.rehashIfNeeded(password, currentHash, 12);

      // Assert
      expect(result).toBeNull();
    });

    it('should return new hash if current rounds are lower', async () => {
      // Arrange
      const password = 'TestPassword123!';
      // Simulate a hash with lower rounds
      const currentHash = '$2b$10$R9h/cIPz0gi.URNNX3kh2ORAN4QcxlK2PqVWfA6pLy5g5gN5GU2oK';

      // Act
      const result = await service.rehashIfNeeded(password, currentHash, 12);

      // Assert
      expect(result).not.toBeNull();
      expect(result).toMatch(/^\$2[abyxz]\$12\$/);
    });

    it('should return new hash for invalid hash format', async () => {
      // Arrange
      const password = 'TestPassword123!';
      const invalidHash = 'invalid.hash.format';

      // Act
      const result = await service.rehashIfNeeded(password, invalidHash);

      // Assert
      expect(result).not.toBeNull();
      expect(result).toMatch(/^\$2[abyxz]\$12\$/);
    });
  });

  describe('isPasswordCompromised', () => {
    it('should return true for common weak passwords', async () => {
      // Arrange
      const weakPasswords = [
        'password',
        'Password123',
        'admin123',
        'LETMEIN',
      ];

      // Act & Assert
      weakPasswords.forEach(password => {
        expect(service.isPasswordCompromised(password)).toBe(true);
      });
    });

    it('should return false for strong passwords', async () => {
      // Arrange
      const strongPasswords = [
        'MyUniquePassword123!',
        'SecureComplexPass@2023',
        'UncommonPhrase#789',
      ];

      // Act & Assert
      strongPasswords.forEach(password => {
        expect(service.isPasswordCompromised(password)).toBe(false);
      });
    });
  });

  describe('generatePasswordStrengthScore', () => {
    it('should return 0 for empty password', async () => {
      // Act
      const score = service.generatePasswordStrengthScore('');

      // Assert
      expect(score).toBe(0);
    });

    it('should return high score for strong password', async () => {
      // Arrange
      const strongPassword = 'MyVeryStrongPassword123!@#';

      // Act
      const score = service.generatePasswordStrengthScore(strongPassword);

      // Assert
      expect(score).toBeGreaterThan(5);
    });

    it('should return low score for weak password', async () => {
      // Arrange
      const weakPassword = 'password';

      // Act
      const score = service.generatePasswordStrengthScore(weakPassword);

      // Assert
      expect(score).toBeLessThan(3);
    });

    it('should penalize repeated characters', async () => {
      // Arrange
      const repeatedPassword = 'AAA123!@#';
      const normalPassword = 'ABC123!@#';

      // Act
      const repeatedScore = service.generatePasswordStrengthScore(repeatedPassword);
      const normalScore = service.generatePasswordStrengthScore(normalPassword);

      // Assert
      expect(repeatedScore).toBeLessThan(normalScore);
    });
  });
});
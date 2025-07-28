import { Test, TestingModule } from '@nestjs/testing';
import { BcryptPasswordHashingService } from './bcrypt-password-hashing.service';

describe('BcryptPasswordHashingService (Integration)', () => {
  let service: BcryptPasswordHashingService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [BcryptPasswordHashingService],
    }).compile();

    service = module.get<BcryptPasswordHashingService>(BcryptPasswordHashingService);
  });

  describe('Real bcrypt operations', () => {
    it('should hash and verify password correctly', async () => {
      const plainPassword = 'TestPassword123!@#';

      // Hash the password
      const hashedPassword = await service.hash(plainPassword);

      // Verify the hash format
      expect(hashedPassword).toMatch(/^\$2[aby]\$\d{2}\$.{53}$/);

      // Verify the password
      const isValid = await service.compare(plainPassword, hashedPassword);
      expect(isValid).toBe(true);

      // Verify wrong password fails
      const isInvalid = await service.compare('WrongPassword', hashedPassword);
      expect(isInvalid).toBe(false);
    });

    it('should generate unique hashes for same password', async () => {
      const plainPassword = 'SamePassword123!';

      const hash1 = await service.hash(plainPassword);
      const hash2 = await service.hash(plainPassword);

      // Hashes should be different (due to random salt)
      expect(hash1).not.toBe(hash2);

      // But both should verify correctly
      expect(await service.compare(plainPassword, hash1)).toBe(true);
      expect(await service.compare(plainPassword, hash2)).toBe(true);
    });

    it('should handle different salt rounds correctly', async () => {
      const plainPassword = 'TestPassword123!';

      // Test with different salt rounds
      const hash10 = await service.hash(plainPassword, 10);
      const hash12 = await service.hash(plainPassword, 12);

      // Both should verify correctly
      expect(await service.compare(plainPassword, hash10)).toBe(true);
      expect(await service.compare(plainPassword, hash12)).toBe(true);

      // Verify rounds are correct
      expect(service.getRounds(hash10)).toBe(10);
      expect(service.getRounds(hash12)).toBe(12);
    });

    it('should generate and use salt correctly', async () => {
      const plainPassword = 'TestPassword123!';

      // Generate salt
      const salt = await service.generateSalt(12);
      expect(salt).toMatch(/^\$2[aby]\$12\$.{22}$/);

      // Hash with generated salt
      const hashedPassword = await service.hashWithSalt(plainPassword, salt);
      expect(hashedPassword).toMatch(/^\$2[aby]\$12\$.{53}$/);

      // Verify the password
      const isValid = await service.compare(plainPassword, hashedPassword);
      expect(isValid).toBe(true);
    });

    it('should detect rehash requirements correctly', async () => {
      const plainPassword = 'TestPassword123!';

      // Create hash with lower rounds
      const oldHash = await service.hash(plainPassword, 10);
      
      // Should need rehash with higher rounds
      expect(service.needsRehash(oldHash, 12)).toBe(true);
      
      // Should not need rehash with same rounds
      expect(service.needsRehash(oldHash, 10)).toBe(false);
      
      // Should not need rehash with lower rounds
      expect(service.needsRehash(oldHash, 8)).toBe(false);
    });

    it('should pass health check with real operations', async () => {
      const isHealthy = await service.healthCheck();
      expect(isHealthy).toBe(true);
    });

    it('should handle various password types', async () => {
      const testPasswords = [
        'Simple123',
        'Complex!@#$%^&*()Password123',
        '密码123', // Chinese characters
        'Пароль123', // Cyrillic characters
        'пароль-with-special-chars!@#',
        '🔐SecurePassword123🔑', // Emoji
        'A'.repeat(128), // Maximum length
      ];

      for (const password of testPasswords) {
        const hash = await service.hash(password);
        const isValid = await service.compare(password, hash);
        expect(isValid).toBe(true);
      }
    });

    it('should maintain consistency across multiple operations', async () => {
      const plainPassword = 'ConsistencyTest123!';
      const iterations = 10;
      const hashes: string[] = [];

      // Generate multiple hashes
      for (let i = 0; i < iterations; i++) {
        const hash = await service.hash(plainPassword);
        hashes.push(hash);
      }

      // All hashes should be unique
      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).toBe(iterations);

      // All hashes should verify correctly
      for (const hash of hashes) {
        const isValid = await service.compare(plainPassword, hash);
        expect(isValid).toBe(true);
      }
    });

    it('should handle edge cases correctly', async () => {
      // Test minimum length password
      const minPassword = 'A';
      const minHash = await service.hash(minPassword);
      expect(await service.compare(minPassword, minHash)).toBe(true);

      // Test password with only spaces
      const spacePassword = '   ';
      const spaceHash = await service.hash(spacePassword);
      expect(await service.compare(spacePassword, spaceHash)).toBe(true);

      // Test password with special characters
      const specialPassword = '!@#$%^&*()_+-=[]{}|;:,.<>?';
      const specialHash = await service.hash(specialPassword);
      expect(await service.compare(specialPassword, specialHash)).toBe(true);
    });

    it('should maintain performance within reasonable bounds', async () => {
      const plainPassword = 'PerformanceTest123!';
      const startTime = Date.now();

      // Hash with default rounds (12)
      const hash = await service.hash(plainPassword);
      const hashTime = Date.now() - startTime;

      // Verify with the hash
      const verifyStartTime = Date.now();
      const isValid = await service.compare(plainPassword, hash);
      const verifyTime = Date.now() - verifyStartTime;

      expect(isValid).toBe(true);

      // Hash operation should complete within reasonable time (adjust based on hardware)
      expect(hashTime).toBeLessThan(5000); // 5 seconds max
      expect(verifyTime).toBeLessThan(5000); // 5 seconds max

      console.log(`Hash time: ${hashTime}ms, Verify time: ${verifyTime}ms`);
    });

    it('should maintain security properties', async () => {
      const plainPassword = 'SecurityTest123!';

      // Hash the password
      const hash = await service.hash(plainPassword);

      // Hash should not contain the original password
      expect(hash).not.toContain(plainPassword);
      expect(hash.toLowerCase()).not.toContain(plainPassword.toLowerCase());

      // Hash should be deterministic with same salt
      const salt = await service.generateSalt(12);
      const hash1 = await service.hashWithSalt(plainPassword, salt);
      const hash2 = await service.hashWithSalt(plainPassword, salt);
      expect(hash1).toBe(hash2);

      // Different salts should produce different hashes
      const salt2 = await service.generateSalt(12);
      const hash3 = await service.hashWithSalt(plainPassword, salt2);
      expect(hash1).not.toBe(hash3);
    });
  });

  describe('Configuration and service info', () => {
    it('should return correct configuration', () => {
      const config = service.getConfiguration();

      expect(config).toEqual({
        defaultRounds: 12,
        minRounds: 10,
        maxRounds: 16,
        algorithm: 'bcrypt',
      });
    });

    it('should return recommended rounds', () => {
      const recommendedRounds = service.getRecommendedRounds();
      expect(recommendedRounds).toBe(12);
    });
  });
});
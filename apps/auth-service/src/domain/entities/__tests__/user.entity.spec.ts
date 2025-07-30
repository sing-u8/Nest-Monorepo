import { User } from '../user.entity';
import { AuthProvider } from '@auth/shared/types/auth.types';

describe('User Entity', () => {
  describe('constructor', () => {
    it('should create a user with valid data', () => {
      const user = new User(
        '123',
        'test@example.com',
        'password123',
        'John Doe',
        'profile.jpg',
        AuthProvider.LOCAL,
        undefined,
        true,
        new Date('2024-01-01'),
        new Date('2024-01-01')
      );

      expect(user.id).toBe('123');
      expect(user.email).toBe('test@example.com');
      expect(user.name).toBe('John Doe');
      expect(user.profilePicture).toBe('profile.jpg');
      expect(user.provider).toBe(AuthProvider.LOCAL);
      expect(user.isAccountActive()).toBe(true);
    });

    it('should throw error for invalid email', () => {
      expect(() => {
        new User('123', 'invalid-email', 'password123', 'John Doe');
      }).toThrow('Invalid email format');
    });

    it('should throw error for empty name', () => {
      expect(() => {
        new User('123', 'test@example.com', 'password123', '');
      }).toThrow('Name cannot be empty');
    });

    it('should throw error for name exceeding 100 characters', () => {
      const longName = 'a'.repeat(101);
      expect(() => {
        new User('123', 'test@example.com', 'password123', longName);
      }).toThrow('Name cannot exceed 100 characters');
    });

    it('should throw error for local provider without password', () => {
      expect(() => {
        new User('123', 'test@example.com', '', 'John Doe', undefined, AuthProvider.LOCAL);
      }).toThrow('Password is required for local authentication');
    });

    it('should create social auth user without password', () => {
      const user = new User(
        '123',
        'test@example.com',
        '',
        'John Doe',
        undefined,
        AuthProvider.GOOGLE,
        'google-123'
      );

      expect(user.provider).toBe(AuthProvider.GOOGLE);
      expect(user.providerId).toBe('google-123');
    });
  });

  describe('validatePassword', () => {
    it('should return true for correct password', () => {
      const user = new User('123', 'test@example.com', 'password123', 'John Doe');
      expect(user.validatePassword('password123')).toBe(true);
    });

    it('should return false for incorrect password', () => {
      const user = new User('123', 'test@example.com', 'password123', 'John Doe');
      expect(user.validatePassword('wrongpassword')).toBe(false);
    });

    it('should return false for social auth user', () => {
      const user = new User(
        '123',
        'test@example.com',
        '',
        'John Doe',
        undefined,
        AuthProvider.GOOGLE,
        'google-123'
      );
      expect(user.validatePassword('anypassword')).toBe(false);
    });
  });

  describe('updatePassword', () => {
    it('should update password for local user', () => {
      const user = new User('123', 'test@example.com', 'oldpassword', 'John Doe');
      const oldUpdatedAt = user.getUpdatedAt();

      // Wait a bit to ensure different timestamp
      jest.advanceTimersByTime(100);

      user.updatePassword('newpassword123');
      expect(user.validatePassword('newpassword123')).toBe(true);
      expect(user.validatePassword('oldpassword')).toBe(false);
      expect(user.getUpdatedAt().getTime()).toBeGreaterThan(oldUpdatedAt.getTime());
    });

    it('should throw error for social auth user', () => {
      const user = new User(
        '123',
        'test@example.com',
        '',
        'John Doe',
        undefined,
        AuthProvider.GOOGLE
      );

      expect(() => {
        user.updatePassword('newpassword');
      }).toThrow('Cannot update password for non-local authentication');
    });

    it('should throw error for password less than 8 characters', () => {
      const user = new User('123', 'test@example.com', 'password123', 'John Doe');

      expect(() => {
        user.updatePassword('short');
      }).toThrow('Password must be at least 8 characters long');
    });
  });

  describe('updateProfile', () => {
    it('should update name and profile picture', () => {
      const user = new User('123', 'test@example.com', 'password123', 'John Doe');
      const oldUpdatedAt = user.getUpdatedAt();

      // Wait a bit to ensure different timestamp
      jest.advanceTimersByTime(100);

      user.updateProfile('Jane Doe', 'newprofile.jpg');
      expect(user.name).toBe('Jane Doe');
      expect(user.profilePicture).toBe('newprofile.jpg');
      expect(user.getUpdatedAt().getTime()).toBeGreaterThan(oldUpdatedAt.getTime());
    });

    it('should update only name when profile picture is not provided', () => {
      const user = new User('123', 'test@example.com', 'password123', 'John Doe', 'old.jpg');
      user.updateProfile('Jane Doe');
      
      expect(user.name).toBe('Jane Doe');
      expect(user.profilePicture).toBe('old.jpg');
    });

    it('should throw error for invalid name', () => {
      const user = new User('123', 'test@example.com', 'password123', 'John Doe');

      expect(() => {
        user.updateProfile('');
      }).toThrow('Name cannot be empty');
    });
  });

  describe('account activation/deactivation', () => {
    it('should deactivate active account', () => {
      const user = new User('123', 'test@example.com', 'password123', 'John Doe');
      expect(user.isAccountActive()).toBe(true);

      user.deactivate();
      expect(user.isAccountActive()).toBe(false);
    });

    it('should activate deactivated account', () => {
      const user = new User(
        '123',
        'test@example.com',
        'password123',
        'John Doe',
        undefined,
        AuthProvider.LOCAL,
        undefined,
        false
      );
      expect(user.isAccountActive()).toBe(false);

      user.activate();
      expect(user.isAccountActive()).toBe(true);
    });

    it('should throw error when deactivating already deactivated account', () => {
      const user = new User(
        '123',
        'test@example.com',
        'password123',
        'John Doe',
        undefined,
        AuthProvider.LOCAL,
        undefined,
        false
      );

      expect(() => {
        user.deactivate();
      }).toThrow('User is already deactivated');
    });

    it('should throw error when activating already active account', () => {
      const user = new User('123', 'test@example.com', 'password123', 'John Doe');

      expect(() => {
        user.activate();
      }).toThrow('User is already active');
    });
  });

  describe('toJSON', () => {
    it('should not include password in JSON representation', () => {
      const user = new User('123', 'test@example.com', 'password123', 'John Doe');
      const json = user.toJSON();

      expect(json.password).toBeUndefined();
      expect(json).toMatchObject({
        id: '123',
        email: 'test@example.com',
        name: 'John Doe',
        provider: AuthProvider.LOCAL,
        isActive: true,
      });
    });
  });
});
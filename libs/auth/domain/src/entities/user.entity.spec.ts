import { User } from './user.entity';
import { AuthProvider, UserStatus } from '@auth/shared';

describe('User Entity', () => {
  describe('constructor', () => {
    it('should create a user with valid data', () => {
      const user = new User(
        '123',
        'test@example.com',
        'Password123!',
        'Test User'
      );

      expect(user.id).toBe('123');
      expect(user.email).toBe('test@example.com');
      expect(user.name).toBe('Test User');
      expect(user.provider).toBe(AuthProvider.LOCAL);
      expect(user.isAccountActive()).toBe(true);
    });

    it('should throw error for invalid email', () => {
      expect(() => {
        new User('123', 'invalid-email', 'Password123!', 'Test User');
      }).toThrow('Invalid email format');
    });

    it('should throw error for weak password', () => {
      expect(() => {
        new User('123', 'test@example.com', 'weak', 'Test User');
      }).toThrow('Password must be at least 8 characters long');
    });

    it('should not validate password for social providers', () => {
      const user = new User(
        '123',
        'test@example.com',
        '', // Empty password
        'Test User',
        undefined,
        AuthProvider.GOOGLE,
        'google-123'
      );

      expect(user).toBeDefined();
      expect(user.provider).toBe(AuthProvider.GOOGLE);
    });
  });

  describe('create factory method', () => {
    it('should create a user using factory method', () => {
      const user = User.create({
        id: '123',
        email: 'test@example.com',
        password: 'Password123!',
        name: 'Test User',
      });

      expect(user).toBeInstanceOf(User);
      expect(user.email).toBe('test@example.com');
    });
  });

  describe('createFromSocialProvider factory method', () => {
    it('should create a social login user', () => {
      const user = User.createFromSocialProvider({
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
        provider: AuthProvider.GOOGLE,
        providerId: 'google-123',
        profilePicture: 'https://example.com/pic.jpg',
      });

      expect(user).toBeInstanceOf(User);
      expect(user.provider).toBe(AuthProvider.GOOGLE);
      expect(user.providerId).toBe('google-123');
      expect(user.profilePicture).toBe('https://example.com/pic.jpg');
    });
  });

  describe('password validation', () => {
    let user: User;

    beforeEach(() => {
      user = new User('123', 'test@example.com', 'Password123!', 'Test User');
    });

    it('should validate correct password', () => {
      expect(user.validatePassword('Password123!')).toBe(true);
    });

    it('should reject incorrect password', () => {
      expect(user.validatePassword('WrongPassword')).toBe(false);
    });
  });

  describe('updatePassword', () => {
    let user: User;

    beforeEach(() => {
      user = new User('123', 'test@example.com', 'Password123!', 'Test User');
    });

    it('should update password with valid new password', () => {
      user.updatePassword('NewPassword123!');
      expect(user.validatePassword('NewPassword123!')).toBe(true);
      expect(user.validatePassword('Password123!')).toBe(false);
    });

    it('should throw error when updating password for social provider', () => {
      const socialUser = User.createFromSocialProvider({
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
        provider: AuthProvider.GOOGLE,
        providerId: 'google-123',
      });

      expect(() => {
        socialUser.updatePassword('NewPassword123!');
      }).toThrow('Cannot update password for non-local authentication provider');
    });

    it('should throw error for weak new password', () => {
      expect(() => {
        user.updatePassword('weak');
      }).toThrow('Password must be at least 8 characters long');
    });
  });

  describe('updateProfile', () => {
    let user: User;

    beforeEach(() => {
      user = new User('123', 'test@example.com', 'Password123!', 'Test User');
    });

    it('should update profile with valid data', () => {
      user.updateProfile('New Name', 'https://example.com/new-pic.jpg');
      expect(user.name).toBe('New Name');
      expect(user.profilePicture).toBe('https://example.com/new-pic.jpg');
    });

    it('should update only name when profile picture is not provided', () => {
      const originalPicture = user.profilePicture;
      user.updateProfile('New Name');
      expect(user.name).toBe('New Name');
      expect(user.profilePicture).toBe(originalPicture);
    });

    it('should throw error for empty name', () => {
      expect(() => {
        user.updateProfile('');
      }).toThrow('Name cannot be empty');
    });

    it('should trim whitespace from name', () => {
      user.updateProfile('  New Name  ');
      expect(user.name).toBe('New Name');
    });
  });

  describe('account status management', () => {
    let user: User;

    beforeEach(() => {
      user = new User('123', 'test@example.com', 'Password123!', 'Test User');
    });

    describe('deactivate', () => {
      it('should deactivate active account', () => {
        user.deactivate();
        expect(user.isAccountActive()).toBe(false);
        expect(user.getStatus()).toBe(UserStatus.INACTIVE);
      });

      it('should throw error when deactivating deleted account', () => {
        user.softDelete();
        expect(() => {
          user.deactivate();
        }).toThrow('Cannot deactivate deleted account');
      });
    });

    describe('activate', () => {
      it('should activate inactive account', () => {
        user.deactivate();
        user.activate();
        expect(user.isAccountActive()).toBe(true);
        expect(user.getStatus()).toBe(UserStatus.ACTIVE);
      });

      it('should throw error when activating deleted account', () => {
        user.softDelete();
        expect(() => {
          user.activate();
        }).toThrow('Cannot activate deleted account');
      });

      it('should throw error when activating suspended account', () => {
        user.suspend();
        expect(() => {
          user.activate();
        }).toThrow('Cannot activate suspended account without admin intervention');
      });
    });

    describe('suspend', () => {
      it('should suspend active account', () => {
        user.suspend();
        expect(user.isAccountActive()).toBe(false);
        expect(user.getStatus()).toBe(UserStatus.SUSPENDED);
      });

      it('should throw error when suspending deleted account', () => {
        user.softDelete();
        expect(() => {
          user.suspend();
        }).toThrow('Cannot suspend deleted account');
      });
    });

    describe('softDelete', () => {
      it('should soft delete account', () => {
        user.softDelete();
        expect(user.isAccountActive()).toBe(false);
        expect(user.getStatus()).toBe(UserStatus.DELETED);
      });
    });
  });

  describe('password strength validation', () => {
    it('should require minimum length', () => {
      expect(() => {
        new User('123', 'test@example.com', 'Pass1!', 'Test User');
      }).toThrow('Password must be at least 8 characters long');
    });

    it('should require uppercase letter', () => {
      expect(() => {
        new User('123', 'test@example.com', 'password123!', 'Test User');
      }).toThrow('Password must contain at least one uppercase letter');
    });

    it('should require lowercase letter', () => {
      expect(() => {
        new User('123', 'test@example.com', 'PASSWORD123!', 'Test User');
      }).toThrow('Password must contain at least one lowercase letter');
    });

    it('should require number', () => {
      expect(() => {
        new User('123', 'test@example.com', 'Password!', 'Test User');
      }).toThrow('Password must contain at least one number');
    });

    it('should require special character', () => {
      expect(() => {
        new User('123', 'test@example.com', 'Password123', 'Test User');
      }).toThrow('Password must contain at least one special character');
    });
  });

  describe('toObject', () => {
    it('should convert user to plain object', () => {
      const user = new User('123', 'test@example.com', 'Password123!', 'Test User');
      const obj = user.toObject();

      expect(obj).toEqual({
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
        profilePicture: undefined,
        provider: AuthProvider.LOCAL,
        providerId: undefined,
        status: UserStatus.ACTIVE,
        createdAt: expect.any(Date),
        updatedAt: expect.any(Date),
      });
    });

    it('should not include password in object', () => {
      const user = new User('123', 'test@example.com', 'Password123!', 'Test User');
      const obj = user.toObject();

      expect(obj['password']).toBeUndefined();
    });
  });
});
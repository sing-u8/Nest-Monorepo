
import { Password } from './password.vo';

describe('Password Value Object', () => {
	describe('create', () => {
		it('유효한 비밀번호로 생성되어야 한다', () => {
			const validPassword = 'StrongPass123!';
			const password = Password.create(validPassword);

			expect(password.getValue()).toBe(validPassword);
		});

		it('너무 짧은 비밀번호로 생성 시 예외가 발생해야 한다', () => {
			const shortPassword = '123';

			expect(() => Password.create(shortPassword)).toThrow('비밀번호는 최소 8자 이상이어야 합니다');
		});

		it('너무 긴 비밀번호로 생성 시 예외가 발생해야 한다', () => {
			const longPassword = 'a'.repeat(129);

			expect(() => Password.create(longPassword)).toThrow('비밀번호는 최대 128자를 초과할 수 없습니다');
		});

		it('빈 문자열로 생성 시 예외가 발생해야 한다', () => {
			expect(() => Password.create('')).toThrow('비밀번호는 필수입니다');
		});

		it('null 또는 undefined로 생성 시 예외가 발생해야 한다', () => {
			expect(() => Password.create(null as any)).toThrow('비밀번호는 필수입니다');
			expect(() => Password.create(undefined as any)).toThrow('비밀번호는 필수입니다');
		});
	});

	describe('getStrength', () => {
		it('약한 비밀번호는 낮은 점수를 반환해야 한다', () => {
			const weakPassword = Password.create('password');
			expect(weakPassword.getStrength()).toBeLessThan(3);
		});

		it('강한 비밀번호는 높은 점수를 반환해야 한다', () => {
			const strongPassword = Password.create('StrongPass123!@#');
			expect(strongPassword.getStrength()).toBeGreaterThanOrEqual(4);
		});

		it('다양한 문자 조합의 비밀번호는 중간 점수를 반환해야 한다', () => {
			const moderatePassword = Password.create('ModeratePass1');
			const strength = moderatePassword.getStrength();
			expect(strength).toBeGreaterThanOrEqual(2);
			expect(strength).toBeLessThan(5);
		});
	});

	describe('equals', () => {
		it('같은 값의 비밀번호는 동일하다고 판단해야 한다', () => {
			const password1 = Password.create('SamePassword123!');
			const password2 = Password.create('SamePassword123!');

			expect(password1.equals(password2)).toBe(true);
		});

		it('다른 값의 비밀번호는 다르다고 판단해야 한다', () => {
			const password1 = Password.create('Password123!');
			const password2 = Password.create('DifferentPass456@');

			expect(password1.equals(password2)).toBe(false);
		});
	});

	describe('toJSON', () => {
		it('JSON 변환 시 비밀번호 값이 숨겨져야 한다', () => {
			const password = Password.create('SecretPassword123!');
			const json = password.toJSON();

			expect(json.value).toBe('***');
			expect(json.length).toBe(18);
		});
	});

	describe('edge cases', () => {
		it('공백만 포함된 비밀번호는 유효하지 않아야 한다', () => {
			expect(() => Password.create('        ')).toThrow('비밀번호는 필수입니다');
		});

		it('유니코드 문자가 포함된 비밀번호도 처리할 수 있어야 한다', () => {
			const unicodePassword = Password.create('비밀번호123!@#');
			expect(unicodePassword.getValue()).toBe('비밀번호123!@#');
		});

		it('이모지가 포함된 비밀번호도 처리할 수 있어야 한다', () => {
			const emojiPassword = Password.create('Password123!😊');
			expect(emojiPassword.getValue()).toBe('Password123!😊');
		});
	});
});


/*

	describe('isSecure', () => {
		it('최소 요구사항을 만족하는 비밀번호는 secure 해야 한다', () => {
			const securePassword = Password.create('SecurePass123!');
			expect(securePassword.isSecure()).toBe(true);
		});

		it('요구사항을 만족하지 않는 비밀번호는 secure 하지 않아야 한다', () => {
			const insecurePassword = Password.create('weak');
			expect(insecurePassword.isSecure()).toBe(false);
		});
	});

	describe('hasUpperCase', () => {
		it('대문자가 포함된 비밀번호는 true를 반환해야 한다', () => {
			const password = Password.create('Password123!');
			expect(password.hasUpperCase()).toBe(true);
		});

		it('대문자가 포함되지 않은 비밀번호는 false를 반환해야 한다', () => {
			const password = Password.create('password123!');
			expect(password.hasUpperCase()).toBe(false);
		});
	});

	describe('hasLowerCase', () => {
		it('소문자가 포함된 비밀번호는 true를 반환해야 한다', () => {
			const password = Password.create('PASSWORD123!');
			expect(password.hasLowerCase()).toBe(false);
		});

		it('소문자가 포함되지 않은 비밀번호는 false를 반환해야 한다', () => {
			const password = Password.create('password123!');
			expect(password.hasLowerCase()).toBe(true);
		});
	});

	describe('hasNumber', () => {
		it('숫자가 포함된 비밀번호는 true를 반환해야 한다', () => {
			const password = Password.create('Password123!');
			expect(password.hasNumber()).toBe(true);
		});

		it('숫자가 포함되지 않은 비밀번호는 false를 반환해야 한다', () => {
			const password = Password.create('Password!');
			expect(password.hasNumber()).toBe(false);
		});
	});

	describe('hasSpecialChar', () => {
		it('특수문자가 포함된 비밀번호는 true를 반환해야 한다', () => {
			const password = Password.create('Password123!');
			expect(password.hasSpecialChar()).toBe(true);
		});

		it('특수문자가 포함되지 않은 비밀번호는 false를 반환해야 한다', () => {
			const password = Password.create('Password123');
			expect(password.hasSpecialChar()).toBe(false);
		});
	});

 */

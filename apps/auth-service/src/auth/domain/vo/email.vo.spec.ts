
import { Email, InvalidEmailException } from './email.vo';

describe('Email Value Object', () => {
	describe('create', () => {
		it('유효한 이메일로 생성되어야 한다', () => {
			const validEmail = 'test@example.com';
			const email = Email.create(validEmail);

			expect(email.getValue()).toBe(validEmail);
		});

		it('이메일을 소문자로 변환해야 한다', () => {
			const mixedCaseEmail = 'Test@Example.Com';
			const email = Email.create(mixedCaseEmail);

			expect(email.getValue()).toBe('test@example.com');
		});

		it('이메일 앞뒤 공백을 제거해야 한다', () => {
			const emailWithSpaces = '  test@example.com  ';
			const email = Email.create(emailWithSpaces);

			expect(email.getValue()).toBe('test@example.com');
		});

		it('유효하지 않은 이메일 형식으로 생성 시 예외가 발생해야 한다', () => {
			const invalidEmails = [
				'invalid-email',
				'test@',
				'@example.com',
				'test@.com',
				'test@com',
				'test.example.com',
				'test @example.com',
				'test@exam ple.com',
				''
			];

			invalidEmails.forEach(invalidEmail => {
				expect(() => Email.create(invalidEmail)).toThrow(InvalidEmailException);
			});
		});

		it('null 또는 undefined로 생성 시 예외가 발생해야 한다', () => {
			expect(() => Email.create(null as any)).toThrow(InvalidEmailException);
			expect(() => Email.create(undefined as any)).toThrow(InvalidEmailException);
		});

		it('빈 문자열로 생성 시 예외가 발생해야 한다', () => {
			expect(() => Email.create('')).toThrow(InvalidEmailException);
		});

		it('공백만 포함된 문자열로 생성 시 예외가 발생해야 한다', () => {
			expect(() => Email.create('   ')).toThrow(InvalidEmailException);
		});

		it('최대 길이를 초과하는 이메일로 생성 시 예외가 발생해야 한다', () => {
			const longEmail = 'a'.repeat(250) + '@example.com';
			expect(() => Email.create(longEmail)).toThrow(InvalidEmailException);
		});
	});

	describe('getDomain', () => {
		it('이메일 도메인을 반환해야 한다', () => {
			const email = Email.create('test@example.com');
			expect(email.getDomain()).toBe('example.com');
		});

		it('서브도메인이 있는 경우 전체 도메인을 반환해야 한다', () => {
			const email = Email.create('test@mail.google.com');
			expect(email.getDomain()).toBe('mail.google.com');
		});

		it('국가 도메인도 처리해야 한다', () => {
			const email = Email.create('test@example.co.kr');
			expect(email.getDomain()).toBe('example.co.kr');
		});
	});

	describe('getLocalPart', () => {
		it('이메일 로컬 부분을 반환해야 한다', () => {
			const email = Email.create('testuser@example.com');
			expect(email.getLocalPart()).toBe('testuser');
		});

		it('점이 포함된 로컬 부분을 처리해야 한다', () => {
			const email = Email.create('test.user@example.com');
			expect(email.getLocalPart()).toBe('test.user');
		});

		it('숫자가 포함된 로컬 부분을 처리해야 한다', () => {
			const email = Email.create('user123@example.com');
			expect(email.getLocalPart()).toBe('user123');
		});
	});

	describe('equals', () => {
		it('같은 이메일은 동일하다고 판단해야 한다', () => {
			const email1 = Email.create('test@example.com');
			const email2 = Email.create('test@example.com');

			expect(email1.equals(email2)).toBe(true);
		});

		it('대소문자가 다른 같은 이메일은 동일하다고 판단해야 한다', () => {
			const email1 = Email.create('Test@Example.Com');
			const email2 = Email.create('test@example.com');

			expect(email1.equals(email2)).toBe(true);
		});

		it('다른 이메일은 다르다고 판단해야 한다', () => {
			const email1 = Email.create('test1@example.com');
			const email2 = Email.create('test2@example.com');

			expect(email1.equals(email2)).toBe(false);
		});

		it('Email 인스턴스가 아닌 객체와 비교하면 false를 반환해야 한다', () => {
			const email = Email.create('test@example.com');
			expect(email.equals('test@example.com' as any)).toBe(false);
			expect(email.equals(null as any)).toBe(false);
			expect(email.equals(undefined as any)).toBe(false);
		});
	});

	describe('toString', () => {
		it('이메일 문자열을 반환해야 한다', () => {
			const email = Email.create('test@example.com');
			expect(email.toString()).toBe('test@example.com');
		});
	});

	describe('toJSON', () => {
		it('이메일 정보를 JSON 형태로 반환해야 한다', () => {
			const email = Email.create('test@example.com');
			const json = email.toJSON();

			expect(json).toEqual({
				email: 'test@example.com'
			});
		});
	});

	describe('edge cases', () => {
		it('유효한 복잡한 이메일 형식을 처리해야 한다', () => {
			const complexEmails = [
				'user+tag@example.com',
				'user.name@example.com',
				'user123@example123.com',
				'test@sub.example.com',
				'a@b.co'
			];

			complexEmails.forEach(email => {
				expect(() => Email.create(email)).not.toThrow();
			});
		});

		it('국제 도메인 이름을 처리해야 한다', () => {
			const internationalEmail = 'test@한국.com';
			// 실제로는 punycode로 변환되어야 하지만, 간단한 테스트로 처리
			expect(() => Email.create(internationalEmail)).not.toThrow();
		});
	});
});

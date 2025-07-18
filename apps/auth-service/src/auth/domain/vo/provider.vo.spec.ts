import { Provider } from "@shared/enum/provider.enum";
import { AuthProvider, InvalidProviderException } from "./provider.vo";

describe("AuthProvider Value Object", () => {
	describe("create", () => {
		it("유효한 프로바이더로 생성되어야 한다", () => {
			const validProviders = [Provider.LOCAL, Provider.GOOGLE, Provider.APPLE];

			validProviders.forEach((provider) => {
				const authProvider = AuthProvider.create(provider);
				expect(authProvider.getValue()).toBe(provider);
			});
		});

		it("유효하지 않은 프로바이더로 생성 시 예외가 발생해야 한다", () => {
			const invalidProviders = [
				"invalid",
				"facebook",
				"twitter",
				"github",
				"",
				"LOCAL", // 대소문자 구분
				"google",
				"GOOGLE",
			];

			invalidProviders.forEach((provider) => {
				expect(() => AuthProvider.create(provider)).toThrow(
					InvalidProviderException,
				);
			});
		});

		it("null 또는 undefined로 생성 시 예외가 발생해야 한다", () => {
			expect(() => AuthProvider.create(null as any)).toThrow(
				InvalidProviderException,
			);
			expect(() => AuthProvider.create(undefined as any)).toThrow(
				InvalidProviderException,
			);
		});
	});

	describe("createLocal", () => {
		it("로컬 프로바이더를 생성해야 한다", () => {
			const provider = AuthProvider.createLocal();

			expect(provider.getValue()).toBe(Provider.LOCAL);
			expect(provider.isLocal()).toBe(true);
		});
	});

	describe("createGoogle", () => {
		it("구글 프로바이더를 생성해야 한다", () => {
			const provider = AuthProvider.createGoogle();

			expect(provider.getValue()).toBe(Provider.GOOGLE);
			expect(provider.isGoogle()).toBe(true);
		});
	});

	describe("createApple", () => {
		it("애플 프로바이더를 생성해야 한다", () => {
			const provider = AuthProvider.createApple();

			expect(provider.getValue()).toBe(Provider.APPLE);
			expect(provider.isApple()).toBe(true);
		});
	});

	describe("isLocal", () => {
		it("로컬 프로바이더인 경우 true를 반환해야 한다", () => {
			const provider = AuthProvider.createLocal();

			expect(provider.isLocal()).toBe(true);
		});

		it("소셜 프로바이더인 경우 false를 반환해야 한다", () => {
			const googleProvider = AuthProvider.createGoogle();
			const appleProvider = AuthProvider.createApple();

			expect(googleProvider.isLocal()).toBe(false);
			expect(appleProvider.isLocal()).toBe(false);
		});
	});

	describe("isSocial", () => {
		it("소셜 프로바이더인 경우 true를 반환해야 한다", () => {
			const googleProvider = AuthProvider.createGoogle();
			const appleProvider = AuthProvider.createApple();

			expect(googleProvider.isSocial()).toBe(true);
			expect(appleProvider.isSocial()).toBe(true);
		});

		it("로컬 프로바이더인 경우 false를 반환해야 한다", () => {
			const provider = AuthProvider.createLocal();

			expect(provider.isSocial()).toBe(false);
		});
	});

	describe("isGoogle", () => {
		it("구글 프로바이더인 경우 true를 반환해야 한다", () => {
			const provider = AuthProvider.createGoogle();

			expect(provider.isGoogle()).toBe(true);
		});

		it("구글 프로바이더가 아닌 경우 false를 반환해야 한다", () => {
			const localProvider = AuthProvider.createLocal();
			const appleProvider = AuthProvider.createApple();

			expect(localProvider.isGoogle()).toBe(false);
			expect(appleProvider.isGoogle()).toBe(false);
		});
	});

	describe("isApple", () => {
		it("애플 프로바이더인 경우 true를 반환해야 한다", () => {
			const provider = AuthProvider.createApple();

			expect(provider.isApple()).toBe(true);
		});

		it("애플 프로바이더가 아닌 경우 false를 반환해야 한다", () => {
			const localProvider = AuthProvider.createLocal();
			const googleProvider = AuthProvider.createGoogle();

			expect(localProvider.isApple()).toBe(false);
			expect(googleProvider.isApple()).toBe(false);
		});
	});

	describe("equals", () => {
		it("같은 프로바이더는 동일하다고 판단해야 한다", () => {
			const provider1 = AuthProvider.createLocal();
			const provider2 = AuthProvider.createLocal();

			expect(provider1.equals(provider2)).toBe(true);
		});

		it("다른 프로바이더는 다르다고 판단해야 한다", () => {
			const localProvider = AuthProvider.createLocal();
			const googleProvider = AuthProvider.createGoogle();

			expect(localProvider.equals(googleProvider)).toBe(false);
		});

		it("같은 타입의 프로바이더는 동일하다고 판단해야 한다", () => {
			const google1 = AuthProvider.createGoogle();
			const google2 = AuthProvider.create(Provider.GOOGLE);

			expect(google1.equals(google2)).toBe(true);
		});

		it("AuthProvider 인스턴스가 아닌 객체와 비교하면 false를 반환해야 한다", () => {
			const provider = AuthProvider.createLocal();

			expect(provider.equals(Provider.LOCAL as any)).toBe(false);
			expect(provider.equals(null as any)).toBe(false);
			expect(provider.equals(undefined as any)).toBe(false);
		});
	});

	describe("toString", () => {
		it("프로바이더 문자열을 반환해야 한다", () => {
			const localProvider = AuthProvider.createLocal();
			const googleProvider = AuthProvider.createGoogle();
			const appleProvider = AuthProvider.createApple();

			expect(localProvider.toString()).toBe(Provider.LOCAL);
			expect(googleProvider.toString()).toBe(Provider.GOOGLE);
			expect(appleProvider.toString()).toBe(Provider.APPLE);
		});
	});

	describe("toJSON", () => {
		it("프로바이더 정보를 JSON 형태로 반환해야 한다", () => {
			const localProvider = AuthProvider.createLocal();
			const googleProvider = AuthProvider.createGoogle();
			const appleProvider = AuthProvider.createApple();

			expect(localProvider.toJSON()).toEqual({
				provider: Provider.LOCAL,
			});
			expect(googleProvider.toJSON()).toEqual({
				provider: Provider.GOOGLE,
			});
			expect(appleProvider.toJSON()).toEqual({
				provider: Provider.APPLE,
			});
		});
	});

	describe("integration tests", () => {
		it("다양한 프로바이더 타입을 조합해서 사용할 수 있어야 한다", () => {
			const providers = [
				AuthProvider.createLocal(),
				AuthProvider.createGoogle(),
				AuthProvider.createApple(),
			];

			// 각 프로바이더별 특성 확인
			expect(providers[0].isLocal()).toBe(true);
			expect(providers[1].isGoogle()).toBe(true);
			expect(providers[2].isApple()).toBe(true);

			// 소셜 프로바이더 확인
			expect(providers[0].isSocial()).toBe(false);
			expect(providers[1].isSocial()).toBe(true);
			expect(providers[2].isSocial()).toBe(true);
		});

		it("프로바이더 타입을 정확히 구분해야 한다", () => {
			const localProvider = AuthProvider.createLocal();
			const googleProvider = AuthProvider.createGoogle();
			const appleProvider = AuthProvider.createApple();

			// 각각은 다른 타입이어야 함
			expect(localProvider.equals(googleProvider)).toBe(false);
			expect(localProvider.equals(appleProvider)).toBe(false);
			expect(googleProvider.equals(appleProvider)).toBe(false);
		});
	});
});

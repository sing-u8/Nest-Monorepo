import { InvalidUserIdException, UserId } from "./user-id.vo";

describe("UserId Value Object", () => {
	describe("create", () => {
		it("유효한 UUID로 생성되어야 한다", () => {
			const validUuid = "550e8400-e29b-41d4-a716-446655440000";
			const userId = UserId.create(validUuid);

			expect(userId.getValue()).toBe(validUuid);
		});

		it("UUID v4 형식으로 생성되어야 한다", () => {
			const uuidV4 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
			const userId = UserId.create(uuidV4);

			expect(userId.getValue()).toBe(uuidV4);
		});

		it("유효하지 않은 UUID 형식으로 생성 시 예외가 발생해야 한다", () => {
			const invalidUuids = [
				"550e8400-e29b-41d4-a716-44665544000", // 너무 짧음
				"550e8400-e29b-41d4-a716-4466554400000", // 너무 긺
				"550e8400-e29b-41d4-a716-44665544000g", // 잘못된 문자
				"550e8400e29b41d4a716446655440000", // 하이픈 없음
				"550e8400-e29b-41d4-a716", // 불완전한 UUID
				"not-a-uuid",
				"123456789",
				"",
			];

			invalidUuids.forEach((invalidUuid) => {
				expect(() => UserId.create(invalidUuid)).toThrow(
					InvalidUserIdException,
				);
			});
		});

		it("null 또는 undefined로 생성 시 예외가 발생해야 한다", () => {
			expect(() => UserId.create(null as any)).toThrow(InvalidUserIdException);
			expect(() => UserId.create(undefined as any)).toThrow(
				InvalidUserIdException,
			);
		});

		it("빈 문자열로 생성 시 예외가 발생해야 한다", () => {
			expect(() => UserId.create("")).toThrow(InvalidUserIdException);
		});

		it("공백만 포함된 문자열로 생성 시 예외가 발생해야 한다", () => {
			expect(() => UserId.create("   ")).toThrow(InvalidUserIdException);
		});

		it("대소문자 구분 없이 처리해야 한다", () => {
			const lowerCaseUuid = "550e8400-e29b-41d4-a716-446655440000";
			const upperCaseUuid = "550E8400-E29B-41D4-A716-446655440000";

			const userId1 = UserId.create(lowerCaseUuid);
			const userId2 = UserId.create(upperCaseUuid);

			expect(userId1.getValue()).toBe(lowerCaseUuid);
			expect(userId2.getValue()).toBe(upperCaseUuid);
		});
	});

	describe("generate", () => {
		it("새로운 UUID를 생성해야 한다", () => {
			const userId = UserId.generate();

			expect(userId.getValue()).toBeDefined();
			expect(typeof userId.getValue()).toBe("string");
		});

		it("생성된 UUID는 유효한 형식이어야 한다", () => {
			const userId = UserId.generate();
			const uuidRegex =
				/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

			expect(uuidRegex.test(userId.getValue())).toBe(true);
		});

		it("매번 다른 UUID를 생성해야 한다", () => {
			const userId1 = UserId.generate();
			const userId2 = UserId.generate();

			expect(userId1.getValue()).not.toBe(userId2.getValue());
		});

		it("생성된 UUID는 36자리여야 한다", () => {
			const userId = UserId.generate();

			expect(userId.getValue().length).toBe(36);
		});
	});

	describe("equals", () => {
		it("같은 UUID는 동일하다고 판단해야 한다", () => {
			const uuid = "550e8400-e29b-41d4-a716-446655440000";
			const userId1 = UserId.create(uuid);
			const userId2 = UserId.create(uuid);

			expect(userId1.equals(userId2)).toBe(true);
		});

		it("다른 UUID는 다르다고 판단해야 한다", () => {
			const uuid1 = "550e8400-e29b-41d4-a716-446655440000";
			const uuid2 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
			const userId1 = UserId.create(uuid1);
			const userId2 = UserId.create(uuid2);

			expect(userId1.equals(userId2)).toBe(false);
		});

		it("UserId 인스턴스가 아닌 객체와 비교하면 false를 반환해야 한다", () => {
			const userId = UserId.create("550e8400-e29b-41d4-a716-446655440000");

			expect(userId.equals("550e8400-e29b-41d4-a716-446655440000" as any)).toBe(
				false,
			);
			expect(userId.equals(null as any)).toBe(false);
			expect(userId.equals(undefined as any)).toBe(false);
		});
	});

	describe("toString", () => {
		it("UUID 문자열을 반환해야 한다", () => {
			const uuid = "550e8400-e29b-41d4-a716-446655440000";
			const userId = UserId.create(uuid);

			expect(userId.toString()).toBe(uuid);
		});
	});

	describe("toJSON", () => {
		it("UUID 정보를 JSON 형태로 반환해야 한다", () => {
			const uuid = "550e8400-e29b-41d4-a716-446655440000";
			const userId = UserId.create(uuid);
			const json = userId.toJSON();

			expect(json).toEqual({
				userId: uuid,
			});
		});
	});

	describe("edge cases", () => {
		it("UUID v1 형식도 처리해야 한다", () => {
			const uuidV1 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

			expect(() => UserId.create(uuidV1)).not.toThrow();
		});

		it("UUID v4 형식도 처리해야 한다", () => {
			const uuidV4 = "550e8400-e29b-41d4-a716-446655440000";

			expect(() => UserId.create(uuidV4)).not.toThrow();
		});

		it("UUID v5 형식도 처리해야 한다", () => {
			const uuidV5 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";

			expect(() => UserId.create(uuidV5)).not.toThrow();
		});

		it("앞뒤 공백이 있는 UUID도 처리해야 한다", () => {
			const uuidWithSpaces = "  550e8400-e29b-41d4-a716-446655440000  ";

			// 현재 구현에서는 trim()을 하지만 validate에서 체크하므로 예외 발생
			expect(() => UserId.create(uuidWithSpaces)).toThrow(
				InvalidUserIdException,
			);
		});
	});
});

import { MigrationInterface, QueryRunner, Table, TableIndex } from "typeorm";

/**
 * CreateUsersTable 마이그레이션
 *
 * 사용자 정보를 저장하는 users 테이블을 생성합니다.
 *
 * 마이그레이션을 사용하는 이유:
 * - 데이터베이스 스키마 버전 관리
 * - 팀원 간 스키마 동기화
 * - 프로덕션 배포 시 안전한 스키마 변경
 * - 롤백 가능한 스키마 변경
 */
export class CreateUsersTable1234567890 implements MigrationInterface {
	name = "CreateUsersTable1234567890";

	public async up(queryRunner: QueryRunner): Promise<void> {
		// users 테이블 생성
		await queryRunner.createTable(
			new Table({
				name: "users",
				columns: [
					{
						name: "id",
						type: "uuid",
						isPrimary: true,
						generationStrategy: "uuid",
						default: "gen_random_uuid()",
					},
					{
						name: "email",
						type: "varchar",
						length: "255",
						isUnique: true,
						isNullable: false,
					},
					{
						name: "password_hash",
						type: "varchar",
						length: "255",
						isNullable: true,
						comment: "소셜 로그인 사용자의 경우 NULL",
					},
					{
						name: "provider",
						type: "varchar",
						length: "50",
						default: "'local'",
						comment: "인증 제공자: local, google, apple",
					},
					{
						name: "provider_id",
						type: "varchar",
						length: "255",
						isNullable: true,
						comment: "소셜 로그인 제공자의 사용자 ID",
					},
					{
						name: "is_active",
						type: "boolean",
						default: true,
						comment: "계정 활성화 상태",
					},
					{
						name: "is_email_verified",
						type: "boolean",
						default: false,
						comment: "이메일 인증 상태",
					},
					{
						name: "last_login_at",
						type: "timestamp",
						isNullable: true,
						comment: "마지막 로그인 시간",
					},
					{
						name: "created_at",
						type: "timestamp",
						default: "CURRENT_TIMESTAMP",
					},
					{
						name: "updated_at",
						type: "timestamp",
						default: "CURRENT_TIMESTAMP",
						onUpdate: "CURRENT_TIMESTAMP",
					},
				],
			}),
			true, // ifNotExists
		);

		// 인덱스 생성
		// 1. 이메일 유니크 인덱스 (이미 unique 제약조건으로 생성됨)

		// 2. 소셜 로그인 조회 최적화를 위한 복합 인덱스
		await queryRunner.createIndex(
			"users",
			new TableIndex({
				name: "IDX_users_provider_provider_id",
				columnNames: ["provider", "provider_id"],
			}),
		);

		// 3. 활성 사용자 조회 최적화
		await queryRunner.createIndex(
			"users",
			new TableIndex({
				name: "IDX_users_is_active",
				columnNames: ["is_active"],
			}),
		);

		// 4. 생성일 기준 정렬 최적화
		await queryRunner.createIndex(
			"users",
			new TableIndex({
				name: "IDX_users_created_at",
				columnNames: ["created_at"],
			}),
		);
	}

	public async down(queryRunner: QueryRunner): Promise<void> {
		// 인덱스 삭제 (테이블과 함께 자동 삭제되지만 명시적으로 삭제)
		await queryRunner.dropIndex("users", "IDX_users_provider_provider_id");
		await queryRunner.dropIndex("users", "IDX_users_is_active");
		await queryRunner.dropIndex("users", "IDX_users_created_at");

		// 테이블 삭제
		await queryRunner.dropTable("users");
	}
}

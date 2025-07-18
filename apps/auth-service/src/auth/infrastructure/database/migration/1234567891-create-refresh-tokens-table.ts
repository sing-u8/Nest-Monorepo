import {
	MigrationInterface,
	QueryRunner,
	Table,
	TableForeignKey,
	TableIndex,
} from "typeorm";

/**
 * CreateRefreshTokensTable 마이그레이션
 *
 * 리프레시 토큰을 저장하는 refresh_tokens 테이블을 생성합니다.
 * 사용자와 1:N 관계를 갖습니다.
 */
export class CreateRefreshTokensTable1234567891 implements MigrationInterface {
	name = "CreateRefreshTokensTable1234567891";

	public async up(queryRunner: QueryRunner): Promise<void> {
		// refresh_tokens 테이블 생성
		await queryRunner.createTable(
			new Table({
				name: "refresh_tokens",
				columns: [
					{
						name: "id",
						type: "uuid",
						isPrimary: true,
						generationStrategy: "uuid",
						default: "gen_random_uuid()",
					},
					{
						name: "user_id",
						type: "uuid",
						isNullable: false,
						comment: "사용자 ID (외래 키)",
					},
					{
						name: "token",
						type: "varchar",
						length: "255",
						isUnique: true,
						isNullable: false,
						comment: "해시화된 리프레시 토큰",
					},
					{
						name: "expires_at",
						type: "timestamp",
						isNullable: false,
						comment: "토큰 만료 시간",
					},
					{
						name: "device_info",
						type: "varchar",
						length: "255",
						isNullable: true,
						comment: "디바이스 정보",
					},
					{
						name: "ip_address",
						type: "varchar",
						length: "45",
						isNullable: true,
						comment: "발급 시점 IP 주소 (IPv6 지원)",
					},
					{
						name: "is_active",
						type: "boolean",
						default: true,
						comment: "토큰 활성화 상태",
					},
					{
						name: "last_used_at",
						type: "timestamp",
						isNullable: true,
						comment: "마지막 사용 시간",
					},
					{
						name: "created_at",
						type: "timestamp",
						default: "CURRENT_TIMESTAMP",
					},
				],
			}),
			true, // ifNotExists
		);

		// 인덱스 생성
		// 1. 토큰 값에 대한 유니크 인덱스 (이미 unique 제약조건으로 생성됨)

		// 2. 사용자별 토큰 조회 최적화
		await queryRunner.createIndex(
			"refresh_tokens",
			new TableIndex({
				name: "IDX_refresh_tokens_user_id",
				columnNames: ["user_id"],
			}),
		);

		// 3. 만료된 토큰 정리 최적화
		await queryRunner.createIndex(
			"refresh_tokens",
			new TableIndex({
				name: "IDX_refresh_tokens_expires_at",
				columnNames: ["expires_at"],
			}),
		);

		// 4. 활성 토큰 조회 최적화
		await queryRunner.createIndex(
			"refresh_tokens",
			new TableIndex({
				name: "IDX_refresh_tokens_is_active",
				columnNames: ["is_active"],
			}),
		);

		// 5. 복합 인덱스: 사용자별 활성 토큰 조회
		await queryRunner.createIndex(
			"refresh_tokens",
			new TableIndex({
				name: "IDX_refresh_tokens_user_active",
				columnNames: ["user_id", "is_active"],
			}),
		);

		// 외래 키 제약조건 생성
		await queryRunner.createForeignKey(
			"refresh_tokens",
			new TableForeignKey({
				name: "FK_refresh_tokens_user_id",
				columnNames: ["user_id"],
				referencedTableName: "users",
				referencedColumnNames: ["id"],
				onDelete: "CASCADE", // 사용자 삭제 시 토큰도 자동 삭제
				onUpdate: "CASCADE",
			}),
		);
	}

	public async down(queryRunner: QueryRunner): Promise<void> {
		// 외래 키 제약조건 삭제
		await queryRunner.dropForeignKey(
			"refresh_tokens",
			"FK_refresh_tokens_user_id",
		);

		// 인덱스 삭제
		await queryRunner.dropIndex("refresh_tokens", "IDX_refresh_tokens_user_id");
		await queryRunner.dropIndex(
			"refresh_tokens",
			"IDX_refresh_tokens_expires_at",
		);
		await queryRunner.dropIndex(
			"refresh_tokens",
			"IDX_refresh_tokens_is_active",
		);
		await queryRunner.dropIndex(
			"refresh_tokens",
			"IDX_refresh_tokens_user_active",
		);

		// 테이블 삭제
		await queryRunner.dropTable("refresh_tokens");
	}
}

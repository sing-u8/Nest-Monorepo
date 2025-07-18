import {
	Column,
	CreateDateColumn,
	Entity,
	Index,
	OneToMany,
	PrimaryGeneratedColumn,
	UpdateDateColumn,
} from "typeorm";
import { RefreshTokenTypeOrmEntity } from "./refresh-token.typeorm.entity";

/**
 * User TypeORM 엔티티
 *
 * 이 엔티티는 데이터베이스의 users 테이블과 직접 매핑됩니다.
 * 클린 아키텍처에서는 인프라스트럭처 계층에 속하며,
 * 도메인 엔티티와는 별개의 존재입니다.
 *
 * 설계 원칙:
 * - 데이터베이스 스키마에 최적화
 * - ORM 기능 활용 (관계, 인덱스 등)
 * - 도메인 로직 포함하지 않음
 */
@Entity("users")
@Index(["email"], { unique: true }) // 이메일 유니크 인덱스
@Index(["provider", "providerId"]) // 소셜 로그인 조회 최적화
export class UserTypeOrmEntity {
	/**
	 * 기본 키
	 * UUID를 사용하여 보안성과 확장성을 높입니다.
	 */
	@PrimaryGeneratedColumn("uuid")
	id: string;

	/**
	 * 사용자 이메일
	 * - 유니크 제약조건
	 * - 최대 255자
	 * - NULL 불가
	 */
	@Column({
		type: "varchar",
		length: 255,
		unique: true,
		nullable: false,
	})
	email: string;

	/**
	 * 비밀번호 해시
	 * - 소셜 로그인 사용자의 경우 NULL 가능
	 * - bcrypt 해시 저장 (일반적으로 60자)
	 */
	@Column({
		type: "varchar",
		length: 255,
		nullable: true,
		name: "password_hash",
	})
	passwordHash: string | null;

	/**
	 * 인증 제공자
	 * - 'local': 일반 회원가입
	 * - 'google': Google 소셜 로그인
	 * - 'apple': Apple 소셜 로그인
	 */
	@Column({
		type: "varchar",
		length: 50,
		default: "local",
	})
	provider: string;

	/**
	 * 소셜 로그인 제공자의 사용자 ID
	 * 소셜 로그인시에만 사용됩니다.
	 */
	@Column({
		type: "varchar",
		length: 255,
		nullable: true,
		name: "provider_id",
	})
	providerId: string | null;

	/**
	 * 계정 활성화 상태
	 * - true: 활성화된 계정
	 * - false: 비활성화된 계정 (탈퇴, 정지 등)
	 */
	@Column({
		type: "boolean",
		default: true,
		name: "is_active",
	})
	isActive: boolean;

	/**
	 * 이메일 인증 상태
	 * 이메일 인증 기능을 추가할 때 사용할 수 있습니다.
	 */
	@Column({
		type: "boolean",
		default: false,
		name: "is_email_verified",
	})
	isEmailVerified: boolean;

	/**
	 * 마지막 로그인 시간
	 * 사용자 활동 추적에 활용할 수 있습니다.
	 */
	@Column({
		type: "timestamp",
		nullable: true,
		name: "last_login_at",
	})
	lastLoginAt: Date | null;

	/**
	 * 생성 시간
	 * TypeORM이 자동으로 관리합니다.
	 */
	@CreateDateColumn({
		name: "created_at",
	})
	createdAt: Date;

	/**
	 * 수정 시간
	 * TypeORM이 자동으로 관리합니다.
	 */
	@UpdateDateColumn({
		name: "updated_at",
	})
	updatedAt: Date;

	/**
	 * 리프레시 토큰과의 관계
	 * 일대다 관계: 한 사용자는 여러 개의 리프레시 토큰을 가질 수 있습니다.
	 * (여러 디바이스에서 로그인 가능)
	 */
	@OneToMany(
		() => RefreshTokenTypeOrmEntity,
		(refreshToken) => refreshToken.user,
		{
			onDelete: "CASCADE", // 사용자 삭제 시 관련 토큰들도 자동 삭제
		},
	)
	refreshTokens: RefreshTokenTypeOrmEntity[];

	/**
	 * 소셜 로그인 사용자인지 확인하는 헬퍼 메서드
	 *
	 * 주의: 이는 편의를 위한 메서드이며,
	 * 실제 비즈니스 로직은 도메인 엔티티에 구현해야 합니다.
	 */
	isSocialUser(): boolean {
		return this.provider !== "local";
	}

	/**
	 * 활성화된 사용자인지 확인하는 헬퍼 메서드
	 */
	isActivated(): boolean {
		return this.isActive;
	}
}

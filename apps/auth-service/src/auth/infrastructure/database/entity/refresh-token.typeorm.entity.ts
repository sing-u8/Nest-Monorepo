import {
	Column,
	CreateDateColumn,
	Entity,
	Index,
	JoinColumn,
	ManyToOne,
	PrimaryGeneratedColumn,
} from "typeorm";
import { UserTypeOrmEntity } from "./user.typeorm.entity";

/**
 * RefreshToken TypeORM 엔티티
 *
 * 리프레시 토큰을 데이터베이스에 저장하여 관리합니다.
 * 이렇게 하는 이유:
 * - 토큰 무효화 가능 (로그아웃, 보안 사고 시)
 * - 다중 디바이스 로그인 관리
 * - 토큰 사용 추적
 * - 보안 강화 (토큰 재사용 방지)
 */
@Entity("refresh_tokens")
@Index(["token"], { unique: true }) // 토큰 값에 유니크 인덱스
@Index(["userId"]) // 사용자별 조회 최적화
@Index(["expiresAt"]) // 만료된 토큰 정리 최적화
export class RefreshTokenTypeOrmEntity {
	/**
	 * 기본 키
	 */
	@PrimaryGeneratedColumn("uuid")
	id: string;

	/**
	 * 사용자 ID (외래 키)
	 */
	@Column({
		type: "uuid",
		name: "user_id",
	})
	userId: string;

	/**
	 * 리프레시 토큰 값
	 * - 유니크 제약조건
	 * - 해시화된 토큰 저장 (보안 강화)
	 */
	@Column({
		type: "varchar",
		length: 255,
		unique: true,
	})
	token: string;

	/**
	 * 토큰 만료 시간
	 * 만료된 토큰은 정기적으로 정리합니다.
	 */
	@Column({
		type: "timestamp",
		name: "expires_at",
	})
	expiresAt: Date;

	/**
	 * 디바이스 정보 (선택사항)
	 * 어떤 디바이스에서 발급된 토큰인지 추적할 수 있습니다.
	 */
	@Column({
		type: "varchar",
		length: 255,
		nullable: true,
		name: "device_info",
	})
	deviceInfo: string | null;

	/**
	 * IP 주소 (선택사항)
	 * 보안 로그를 위해 발급 시점의 IP를 저장할 수 있습니다.
	 */
	@Column({
		type: "varchar",
		length: 45, // IPv6까지 지원
		nullable: true,
		name: "ip_address",
	})
	ipAddress: string | null;

	/**
	 * 토큰 활성화 상태
	 * - true: 활성화된 토큰
	 * - false: 무효화된 토큰 (로그아웃, 보안 사고 등)
	 */
	@Column({
		type: "boolean",
		default: true,
		name: "is_active",
	})
	isActive: boolean;

	/**
	 * 마지막 사용 시간
	 * 토큰이 언제 마지막으로 사용되었는지 추적합니다.
	 */
	@Column({
		type: "timestamp",
		nullable: true,
		name: "last_used_at",
	})
	lastUsedAt: Date | null;

	/**
	 * 생성 시간
	 */
	@CreateDateColumn({
		name: "created_at",
	})
	createdAt: Date;

	/**
	 * 사용자와의 관계
	 * 다대일 관계: 여러 토큰이 한 사용자에게 속합니다.
	 */
	@ManyToOne(
		() => UserTypeOrmEntity,
		(user) => user.refreshTokens,
		{
			onDelete: "CASCADE", // 사용자 삭제 시 토큰도 자동 삭제
		},
	)
	@JoinColumn({ name: "user_id" })
	user: UserTypeOrmEntity;

	/**
	 * 토큰이 만료되었는지 확인하는 헬퍼 메서드
	 */
	isExpired(): boolean {
		return new Date() > this.expiresAt;
	}

	/**
	 * 토큰이 유효한지 확인하는 헬퍼 메서드
	 * (만료되지 않고 활성화된 토큰)
	 */
	isValid(): boolean {
		return this.isActive && !this.isExpired();
	}

	/**
	 * 토큰을 무효화하는 헬퍼 메서드
	 */
	deactivate(): void {
		this.isActive = false;
	}

	/**
	 * 토큰 사용 시간을 업데이트하는 헬퍼 메서드
	 */
	updateLastUsed(): void {
		this.lastUsedAt = new Date();
	}
}

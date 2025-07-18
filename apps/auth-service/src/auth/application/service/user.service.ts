import { Inject, Injectable } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { Provider } from '@shared/enum/provider.enum';
import { IUserRepository, User,Password, UserId, PasswordDomainService, UserDomainService } from "@/auth/domain";
import {
	InvalidCredentialsException,
	UserNotFoundException,
	USER_REPOSITORY_TOKEN
} from '@/auth/domain';
import {
	ChangePasswordDto,
	GetUsersQueryDto,
	UpdateUserDto,
	UserDetailDto,
	UsersResponseDto,
	VerifyEmailDto,
} from "../dto";
import { UserDeletedEvent } from "../event/event";

/**
 * 사용자 애플리케이션 서비스
 * 사용자 관리, 프로필 업데이트, 비밀번호 변경 등을 담당
 */
@Injectable()
export class UserApplicationService {
	@Inject(USER_REPOSITORY_TOKEN)
	private readonly userRepository: IUserRepository;

	constructor(
		private readonly userDomainService: UserDomainService,
		private readonly passwordDomainService: PasswordDomainService,
		private readonly eventEmitter: EventEmitter2,
	) {}

	/**
	 * 사용자 목록 조회 (관리자용)
	 */
	async getUsers(queryDto: GetUsersQueryDto): Promise<UsersResponseDto> {
		// 페이지네이션 및 필터 옵션 구성
		const searchOptions = {
			page: queryDto.page || 1,
			limit: queryDto.limit || 10,
			sortBy: queryDto.sortBy || "createdAt",
			sortOrder: queryDto.sortOrder || "DESC",
		};

		// 검색 필터 구성
		const filters: any = {};

		if (queryDto.search) {
			// 이메일로 검색 (실제 구현에서는 더 복잡한 검색 로직 가능)
			filters.emailContains = queryDto.search;
		}

		if (queryDto.provider) {
			filters.provider = queryDto.provider;
		}

		if (queryDto.isActive !== undefined) {
			filters.isActive = queryDto.isActive;
		}

		if (queryDto.isEmailVerified !== undefined) {
			filters.isEmailVerified = queryDto.isEmailVerified;
		}

		// 사용자 목록 조회
		const result = await this.userRepository.findMany({
			...searchOptions,
			filters,
		});

		// DTO 변환
		const userDetailDtos = result.items.map((user) =>
			this.createUserDetailDto(user),
		);

		return new UsersResponseDto(
			userDetailDtos,
			result.total,
			result.page,
			result.limit,
		);
	}

	/**
	 * 특정 사용자 조회
	 */
	async getUserById(userId: string): Promise<UserDetailDto> {
		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		return this.createUserDetailDto(user);
	}

	/**
	 * 사용자 프로필 업데이트
	 */
	async updateUser(
		userId: string,
		updateDto: UpdateUserDto,
	): Promise<UserDetailDto> {
		// 사용자 조회
		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		// 이메일 업데이트 (현재 구현에서는 제한)
		if (updateDto.email) {
			// TODO: User 엔티티에 changeEmail 메서드 구현 필요
			// 현재는 이메일 변경을 지원하지 않음
			throw new Error("Email change is not currently supported");
		}

		// 계정 활성화 상태 업데이트
		if (updateDto.isActive !== undefined) {
			if (updateDto.isActive) {
				user.activate();
			} else {
				user.deactivate();
			}
		}

		// 이메일 인증 상태 업데이트 (관리자 권한)
		if (updateDto.isEmailVerified !== undefined) {
			if (updateDto.isEmailVerified) {
				user.verifyEmail();
			}
			// 이메일 인증 취소는 별도 메서드가 필요할 수 있음
		}

		// 저장
		const updatedUser = await this.userRepository.save(user);
		return this.createUserDetailDto(updatedUser);
	}

	/**
	 * 비밀번호 변경
	 */
	async changePassword(
		userId: string,
		changePasswordDto: ChangePasswordDto,
	): Promise<void> {
		// 사용자 조회
		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		// 로컬 계정인지 확인
		if (!user.isLocalAccount()) {
			throw new Error("Cannot change password for social accounts");
		}

		// 현재 비밀번호 검증
		const currentPasswordHash = user.getPasswordHash();
		if (!currentPasswordHash) {
			throw new Error("Password hash not found");
		}

		const isCurrentPasswordValid =
			await this.passwordDomainService.verifyPassword(
				changePasswordDto.currentPassword,
				currentPasswordHash,
			);

		if (!isCurrentPasswordValid) {
			throw new InvalidCredentialsException("Current password is incorrect");
		}

		// 새 비밀번호 해싱 및 업데이트
		const newPassword = Password.create(changePasswordDto.newPassword);
		const newHashedPassword =
			await this.passwordDomainService.hashPassword(newPassword);

		user.changePasswordHash(newHashedPassword);

		// 저장
		await this.userRepository.save(user);
	}

	/**
	 * 사용자 계정 삭제
	 */
	async deleteUser(userId: string, reason?: string): Promise<void> {
		// 사용자 조회
		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		// 삭제 전 검증 (도메인 서비스 사용)
		await this.userDomainService.validateAccountDeletion(userId);

		// 소프트 삭제 수행
		await this.userRepository.softDelete(userIdVO);

		// 도메인 이벤트 발행
		const event = new UserDeletedEvent(
			user.getId(),
			user.getEmail().getValue(),
			user.getProvider()?.getValue() || Provider.LOCAL,
			"user", // deletedBy
			reason || "User requested deletion",
		);
		this.eventEmitter.emit("user.deleted", event);
	}

	/**
	 * 이메일 인증 처리
	 */
	async verifyEmail(verifyEmailDto: VerifyEmailDto): Promise<void> {
		// TODO: 이메일 인증 토큰 검증 로직 구현
		// 1. 토큰에서 사용자 ID 추출
		// 2. 토큰 유효성 검증
		// 3. 사용자 조회 및 이메일 인증 처리

		// 임시 구현: 토큰에서 사용자 ID 추출한다고 가정
		const userId = this.extractUserIdFromToken(verifyEmailDto.token);

		const userIdVO = UserId.create(userId);
		const user = await this.userRepository.findById(userIdVO);

		if (!user) {
			throw new UserNotFoundException(userId);
		}

		// 이메일 인증 처리
		user.verifyEmail();
		await this.userRepository.save(user);
	}

	/**
	 * 사용자 통계 조회 (관리자용)
	 */
	async getUserStats(): Promise<{
		totalUsers: number;
		activeUsers: number;
		verifiedUsers: number;
		localUsers: number;
		socialUsers: number;
	}> {
		// 전체 사용자 수
		const totalResult = await this.userRepository.findMany({
			page: 1,
			limit: 1,
		});
		const totalUsers = totalResult.total;

		// 활성 사용자 수
		const activeUsers = await this.userRepository.countActiveUsers();

		// TODO: 나머지 통계는 리포지토리에 메서드 추가 필요
		// 임시로 0 반환
		return {
			totalUsers,
			activeUsers,
			verifiedUsers: 0,
			localUsers: 0,
			socialUsers: 0,
		};
	}

	/**
	 * UserDetailDto 생성 헬퍼
	 */
	private createUserDetailDto(user: User): UserDetailDto {
		return new UserDetailDto(
			user.getId(),
			user.getEmail().getValue(),
			user.getProvider()?.getValue() || Provider.LOCAL,
			user.isActive(),
			user.isEmailVerified(),
			user.getCreatedAt(),
			user.getUpdatedAt(),
			user.getProviderId(),
			user.getLastLoginAt(),
		);
	}

	/**
	 * 토큰에서 사용자 ID 추출 (임시 구현)
	 */
	private extractUserIdFromToken(token: string): string {
		// TODO: 실제 JWT 토큰 파싱 로직 구현
		// 현재는 토큰 자체가 사용자 ID라고 가정
		return token;
	}
}

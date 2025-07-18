import {
	ArgumentsHost,
	Catch,
	ExceptionFilter,
	HttpStatus,
	Logger,
} from "@nestjs/common";

// Domain Exceptions
import { DomainException } from "../../domain/exception/domain.exception";
import { InvalidCredentialsException } from "../../domain/exception/invalid-credentials.exception";
import { InvalidRefreshTokenException } from "../../domain/exception/invalid-refresh-token.exception";
import { UserAlreadyExistsException } from "../../domain/exception/user-already-exists.exception";
import { UserNotFoundException } from "../../domain/exception/user-not-found.exception";

// Response DTOs
import { BaseResponseDto } from "../dto/responses/auth.response.dto";

/**
 * Domain Exception Filter
 *
 * 도메인 계층에서 발생하는 예외들을 적절한 HTTP 응답으로 변환합니다.
 */
@Catch(DomainException)
export class DomainExceptionFilter implements ExceptionFilter {
	private readonly logger = new Logger(DomainExceptionFilter.name);

	catch(exception: DomainException, host: ArgumentsHost) {
		const ctx = host.switchToHttp();
		const response = ctx.getResponse();
		const request = ctx.getRequest();

		const status = this.getHttpStatus(exception);
		const errorResponse = this.createErrorResponse(exception, status);

		// 로깅
		this.logException(exception, request, status);

		response.status(status).json(errorResponse);
	}

	/**
	 * 도메인 예외를 HTTP 상태 코드로 매핑
	 */
	private getHttpStatus(exception: DomainException): number {
		if (exception instanceof UserAlreadyExistsException) {
			return HttpStatus.CONFLICT; // 409
		}

		if (exception instanceof UserNotFoundException) {
			return HttpStatus.NOT_FOUND; // 404
		}

		if (exception instanceof InvalidCredentialsException) {
			return HttpStatus.UNAUTHORIZED; // 401
		}

		if (exception instanceof InvalidRefreshTokenException) {
			return HttpStatus.UNAUTHORIZED; // 401
		}

		// 기본적으로 400 Bad Request
		return HttpStatus.BAD_REQUEST;
	}

	/**
	 * 에러 응답 생성
	 */
	private createErrorResponse(
		exception: DomainException,
		status: number,
	): BaseResponseDto {
		return new BaseResponseDto({
			success: false,
			message: exception.message,
			error: {
				code: exception.code,
				message: exception.message,
				details: exception.details,
			},
		});
	}

	/**
	 * 예외 로깅
	 */
	private logException(
		exception: DomainException,
		request: any,
		status: number,
	) {
		const { method, url, ip, headers } = request;
		const userAgent = headers["user-agent"] || "Unknown";

		this.logger.error(`${method} ${url} ${status} - ${exception.message}`, {
			timestamp: new Date().toISOString(),
			ip,
			userAgent,
			exceptionCode: exception.code,
			exceptionDetails: exception.details,
			stack: exception.stack,
		});
	}
}

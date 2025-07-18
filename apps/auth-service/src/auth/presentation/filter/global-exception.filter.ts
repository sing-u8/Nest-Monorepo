import {
	ArgumentsHost,
	Catch,
	ExceptionFilter,
	HttpException,
	HttpStatus,
	Logger,
} from "@nestjs/common";
import { BaseResponseDto } from "../dto/responses/auth.response.dto";

/**
 * Global Exception Filter
 *
 * 모든 예외를 처리하는 글로벌 필터입니다.
 * 도메인 예외 필터에서 처리되지 않은 예외들을 처리합니다.
 */
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
	private readonly logger = new Logger(GlobalExceptionFilter.name);

	catch(exception: unknown, host: ArgumentsHost) {
		const ctx = host.switchToHttp();
		const response = ctx.getResponse();
		const request = ctx.getRequest();

		let status: number;
		let message: string;
		let code: string;

		if (exception instanceof HttpException) {
			status = exception.getStatus();
			const responseBody = exception.getResponse();

			if (typeof responseBody === "object" && responseBody !== null) {
				message = (responseBody as any).message || exception.message;
			} else {
				message = exception.message;
			}

			code = `HTTP_${status}`;
		} else if (exception instanceof Error) {
			status = HttpStatus.INTERNAL_SERVER_ERROR;
			message = exception.message || "내부 서버 오류가 발생했습니다.";
			code = "INTERNAL_SERVER_ERROR";
		} else {
			status = HttpStatus.INTERNAL_SERVER_ERROR;
			message = "알 수 없는 오류가 발생했습니다.";
			code = "UNKNOWN_ERROR";
		}

		const errorResponse = new BaseResponseDto({
			success: false,
			message,
			error: {
				code,
				message,
				details:
					process.env.NODE_ENV === "development"
						? (exception as any)?.stack
						: undefined,
			},
		});

		// 로깅
		this.logException(exception, request, status);

		response.status(status).json(errorResponse);
	}

	/**
	 * 예외 로깅
	 */
	private logException(exception: unknown, request: any, status: number) {
		const { method, url, ip, headers } = request;
		const userAgent = headers["user-agent"] || "Unknown";

		const message =
			exception instanceof Error ? exception.message : "Unknown error";
		const stack = exception instanceof Error ? exception.stack : undefined;

		if (status >= 500) {
			this.logger.error(`${method} ${url} ${status} - ${message}`, {
				timestamp: new Date().toISOString(),
				ip,
				userAgent,
				stack,
			});
		} else {
			this.logger.warn(`${method} ${url} ${status} - ${message}`, {
				timestamp: new Date().toISOString(),
				ip,
				userAgent,
			});
		}
	}
}

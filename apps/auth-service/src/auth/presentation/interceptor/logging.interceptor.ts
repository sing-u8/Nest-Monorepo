import {
	CallHandler,
	ExecutionContext,
	Injectable,
	Logger,
	NestInterceptor,
} from "@nestjs/common";
import { Observable } from "rxjs";
import { tap } from "rxjs/operators";

/**
 * Logging Interceptor
 *
 * 요청과 응답을 로깅합니다.
 * 성능 모니터링과 디버깅에 유용합니다.
 */
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
	private readonly logger = new Logger(LoggingInterceptor.name);

	intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
		const request = context.switchToHttp().getRequest();
		const { method, url, ip, headers } = request;
		const userAgent = headers["user-agent"] || "Unknown";
		const startTime = Date.now();

		// 요청 로깅
		this.logger.log(`Incoming Request: ${method} ${url}`, {
			ip,
			userAgent,
			timestamp: new Date().toISOString(),
		});

		return next.handle().pipe(
			tap({
				next: (responseData) => {
					const endTime = Date.now();
					const duration = endTime - startTime;

					// 성공 응답 로깅
					this.logger.log(`Response: ${method} ${url} - ${duration}ms`, {
						ip,
						userAgent,
						duration,
						success: true,
						timestamp: new Date().toISOString(),
					});
				},
				error: (error) => {
					const endTime = Date.now();
					const duration = endTime - startTime;

					// 에러 응답 로깅
					this.logger.error(
						`Error Response: ${method} ${url} - ${duration}ms - ${error.message}`,
						{
							ip,
							userAgent,
							duration,
							success: false,
							error: error.message,
							timestamp: new Date().toISOString(),
						},
					);
				},
			}),
		);
	}
}

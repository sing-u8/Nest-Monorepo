import {
	CallHandler,
	ExecutionContext,
	Injectable,
	NestInterceptor,
} from "@nestjs/common";
import { plainToInstance } from "class-transformer";
import { Observable } from "rxjs";
import { map } from "rxjs/operators";
import { BaseResponseDto } from "../dto/responses/auth.response.dto";

/**
 * Response Interceptor
 *
 * 응답 데이터를 표준화하고 민감한 정보를 제거합니다.
 */
@Injectable()
export class ResponseInterceptor implements NestInterceptor {
	intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
		return next.handle().pipe(
			map((data) => {
				// 이미 BaseResponseDto 형태라면 그대로 반환
				if (data instanceof BaseResponseDto) {
					return this.transformResponse(data);
				}

				// 일반 데이터를 BaseResponseDto로 래핑
				const wrappedResponse = new BaseResponseDto({
					success: true,
					message: "Request processed successfully",
					data,
				});

				return this.transformResponse(wrappedResponse);
			}),
		);
	}

	/**
	 * 응답 데이터 변환 및 민감한 정보 제거
	 */
	private transformResponse(response: BaseResponseDto): any {
		// class-transformer를 사용하여 @Exclude 데코레이터가 적용된 필드 제거
		return plainToInstance(BaseResponseDto, response, {
			excludeExtraneousValues: false,
			enableImplicitConversion: true,
		});
	}
}

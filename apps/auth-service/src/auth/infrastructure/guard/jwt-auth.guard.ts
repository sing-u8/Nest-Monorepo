import {
	CanActivate,
	ExecutionContext,
	Injectable,
	Logger,
	UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";

interface AuthenticatedRequest {
	headers: {
		authorization?: string;
	};
	user?: {
		userId: string;
		email: string;
		iat: number;
		exp: number;
	};
}

export const IS_PUBLIC_KEY = "isPublic";

@Injectable()
export class JwtAuthGuard implements CanActivate {
	private readonly logger = new Logger(JwtAuthGuard.name);

	constructor(
		private readonly jwtService: JwtService,
		private readonly reflector: Reflector,
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		// @Public() 데코레이터가 적용된 엔드포인트는 인증 생략
		const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
			context.getHandler(),
			context.getClass(),
		]);

		if (isPublic) {
			return true;
		}

		const request = context.switchToHttp().getRequest<any>();
		const token = this.extractTokenFromHeader(request);

		if (!token) {
			this.logger.warn("인증 토큰이 제공되지 않음");
			throw new UnauthorizedException("인증 토큰이 필요합니다.");
		}

		try {
			const payload = await this.jwtService.verifyAsync(token);

			// 토큰에서 추출한 사용자 정보를 request 객체에 저장
			request["user"] = {
				userId: payload.sub,
				email: payload.email,
				iat: payload.iat,
				exp: payload.exp,
			};

			this.logger.debug(`사용자 인증 성공: ${payload.email}`);
			return true;
		} catch (error) {
			this.logger.warn(`JWT 토큰 검증 실패: ${error.message}`);

			if (error.name === "TokenExpiredError") {
				throw new UnauthorizedException("토큰이 만료되었습니다.");
			} else if (error.name === "JsonWebTokenError") {
				throw new UnauthorizedException("유효하지 않은 토큰입니다.");
			} else {
				throw new UnauthorizedException("토큰 검증에 실패했습니다.");
			}
		}
	}

	private extractTokenFromHeader(request: any): string | undefined {
		const [type, token] = request.headers.authorization?.split(" ") ?? [];
		return type === "Bearer" ? token : undefined;
	}
}

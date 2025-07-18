import {
	CanActivate,
	ExecutionContext,
	Injectable,
	Logger,
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";

@Injectable()
export class OptionalAuthGuard implements CanActivate {
	private readonly logger = new Logger(OptionalAuthGuard.name);

	constructor(private readonly jwtService: JwtService) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest<any>();
		const token = this.extractTokenFromHeader(request);

		if (!token) {
			// 토큰이 없어도 통과 (선택적 인증)
			return true;
		}

		try {
			const payload = await this.jwtService.verifyAsync(token);

			// 토큰이 유효하면 사용자 정보를 request 객체에 저장
			request["user"] = {
				userId: payload.sub,
				email: payload.email,
				iat: payload.iat,
				exp: payload.exp,
			};

			this.logger.debug(`선택적 인증 성공: ${payload.email}`);
		} catch (error) {
			// 토큰이 유효하지 않아도 통과 (선택적 인증)
			this.logger.debug(`선택적 인증 실패하지만 통과: ${error.message}`);
		}

		return true;
	}

	private extractTokenFromHeader(request: any): string | undefined {
		const [type, token] = request.headers.authorization?.split(" ") ?? [];
		return type === "Bearer" ? token : undefined;
	}
}

import {
	CanActivate,
	ExecutionContext,
	Injectable,
	Logger,
	UnauthorizedException,
} from "@nestjs/common";

@Injectable()
export class RefreshTokenGuard implements CanActivate {
	private readonly logger = new Logger(RefreshTokenGuard.name);

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest<any>();
		const refreshToken = this.extractRefreshTokenFromBody(request);

		if (!refreshToken) {
			this.logger.warn("Refresh 토큰이 제공되지 않음");
			throw new UnauthorizedException("Refresh 토큰이 필요합니다.");
		}

		// Refresh 토큰을 request 객체에 저장하여 컨트롤러에서 사용할 수 있도록 함
		request["refreshToken"] = refreshToken;

		return true;
	}

	private extractRefreshTokenFromBody(request: any): string | undefined {
		return request.body?.refreshToken;
	}
}

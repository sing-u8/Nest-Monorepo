import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";

export interface EmailOptions {
	to: string;
	subject: string;
	template: string;
	context?: Record<string, any>;
}

export interface WelcomeEmailData {
	userName: string;
	verificationUrl?: string;
}

export interface EmailVerificationData {
	userName: string;
	verificationUrl: string;
	expiresIn: string;
}

export interface PasswordResetData {
	userName: string;
	resetUrl: string;
	expiresIn: string;
}

export interface LoginNotificationData {
	userName: string;
	loginTime: string;
	ipAddress: string;
	deviceInfo: string;
}

@Injectable()
export class EmailService {
	private readonly logger = new Logger(EmailService.name);
	private readonly isDevelopment: boolean;

	constructor(private readonly configService: ConfigService) {
		this.isDevelopment = this.configService.get("NODE_ENV") === "development";
	}

	async sendWelcomeEmail(email: string, data: WelcomeEmailData): Promise<void> {
		const emailOptions: EmailOptions = {
			to: email,
			subject: "환영합니다! 회원가입이 완료되었습니다.",
			template: "welcome",
			context: data,
		};

		await this.sendEmail(emailOptions);
	}

	async sendEmailVerification(
		email: string,
		data: EmailVerificationData,
	): Promise<void> {
		const emailOptions: EmailOptions = {
			to: email,
			subject: "이메일 주소를 인증해주세요",
			template: "email-verification",
			context: data,
		};

		await this.sendEmail(emailOptions);
	}

	async sendPasswordReset(
		email: string,
		data: PasswordResetData,
	): Promise<void> {
		const emailOptions: EmailOptions = {
			to: email,
			subject: "비밀번호 재설정 요청",
			template: "password-reset",
			context: data,
		};

		await this.sendEmail(emailOptions);
	}

	async sendLoginNotification(
		email: string,
		data: LoginNotificationData,
	): Promise<void> {
		const emailOptions: EmailOptions = {
			to: email,
			subject: "새로운 로그인 알림",
			template: "login-notification",
			context: data,
		};

		await this.sendEmail(emailOptions);
	}

	async sendSecurityAlert(
		email: string,
		alertType: string,
		data: Record<string, any>,
	): Promise<void> {
		const emailOptions: EmailOptions = {
			to: email,
			subject: "보안 알림",
			template: "security-alert",
			context: {
				alertType,
				...data,
			},
		};

		await this.sendEmail(emailOptions);
	}

	private async sendEmail(options: EmailOptions): Promise<void> {
		try {
			if (this.isDevelopment) {
				// 개발 환경에서는 콘솔에 로그 출력
				this.logEmailToConsole(options);
			} else {
				// 프로덕션 환경에서는 실제 이메일 발송
				await this.sendRealEmail(options);
			}

			this.logger.log(`이메일 발송 성공: ${options.to} - ${options.subject}`);
		} catch (error) {
			this.logger.error(
				`이메일 발송 실패: ${options.to} - ${options.subject}`,
				error,
			);
			throw new Error("이메일 발송에 실패했습니다.");
		}
	}

	private logEmailToConsole(options: EmailOptions): void {
		console.log("\n=== 📧 이메일 발송 (개발 모드) ===");
		console.log(`받는 사람: ${options.to}`);
		console.log(`제목: ${options.subject}`);
		console.log(`템플릿: ${options.template}`);
		console.log(`데이터:`, JSON.stringify(options.context, null, 2));
		console.log("================================\n");
	}

	private async sendRealEmail(options: EmailOptions): Promise<void> {
		// TODO: 실제 이메일 서비스 연동 (예: SendGrid, AWS SES, Nodemailer 등)
		// 현재는 로그만 출력하지만, 실제 서비스에서는 여기에 이메일 발송 로직을 구현

		this.logger.debug("실제 이메일 발송 로직 - 구현 필요", {
			to: options.to,
			subject: options.subject,
			template: options.template,
		});

		// 예시: Nodemailer 사용 시
		/*
    const transporter = nodemailer.createTransporter({
      // SMTP 설정
    });

    await transporter.sendMail({
      from: this.configService.get('EMAIL_FROM'),
      to: options.to,
      subject: options.subject,
      html: await this.renderTemplate(options.template, options.context),
    });
    */
	}

	private async renderTemplate(
		templateName: string,
		context: Record<string, any> = {},
	): Promise<string> {
		// TODO: 템플릿 엔진 연동 (예: Handlebars, Pug 등)
		// 현재는 간단한 HTML 템플릿 반환

		const templates: Record<string, string> = {
			welcome: this.getWelcomeTemplate(context as WelcomeEmailData),
			"email-verification": this.getEmailVerificationTemplate(
				context as EmailVerificationData,
			),
			"password-reset": this.getPasswordResetTemplate(
				context as PasswordResetData,
			),
			"login-notification": this.getLoginNotificationTemplate(
				context as LoginNotificationData,
			),
			"security-alert": this.getSecurityAlertTemplate(context),
		};

		return templates[templateName] || this.getDefaultTemplate(context);
	}

	private getWelcomeTemplate(context: WelcomeEmailData): string {
		return `
      <h1>환영합니다, ${context.userName}님!</h1>
      <p>회원가입이 성공적으로 완료되었습니다.</p>
      ${context.verificationUrl ? `<p><a href="${context.verificationUrl}">이메일 인증하기</a></p>` : ""}
      <p>서비스를 이용해 주셔서 감사합니다.</p>
    `;
	}

	private getEmailVerificationTemplate(context: EmailVerificationData): string {
		return `
      <h1>이메일 주소 인증</h1>
      <p>안녕하세요, ${context.userName}님!</p>
      <p>아래 링크를 클릭하여 이메일 주소를 인증해 주세요.</p>
      <p><a href="${context.verificationUrl}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">이메일 인증하기</a></p>
      <p>이 링크는 ${context.expiresIn} 후에 만료됩니다.</p>
    `;
	}

	private getPasswordResetTemplate(context: PasswordResetData): string {
		return `
      <h1>비밀번호 재설정</h1>
      <p>안녕하세요, ${context.userName}님!</p>
      <p>비밀번호 재설정을 요청하셨습니다.</p>
      <p><a href="${context.resetUrl}" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">비밀번호 재설정하기</a></p>
      <p>이 링크는 ${context.expiresIn} 후에 만료됩니다.</p>
      <p>본인이 요청하지 않았다면 이 이메일을 무시하세요.</p>
    `;
	}

	private getLoginNotificationTemplate(context: LoginNotificationData): string {
		return `
      <h1>새로운 로그인 감지</h1>
      <p>안녕하세요, ${context.userName}님!</p>
      <p>계정에 새로운 로그인이 감지되었습니다.</p>
      <ul>
        <li>로그인 시간: ${context.loginTime}</li>
        <li>IP 주소: ${context.ipAddress}</li>
        <li>디바이스: ${context.deviceInfo}</li>
      </ul>
      <p>본인이 로그인한 것이 아니라면 즉시 비밀번호를 변경하세요.</p>
    `;
	}

	private getSecurityAlertTemplate(context: Record<string, any>): string {
		return `
      <h1>보안 알림</h1>
      <p>계정에 다음과 같은 보안 이벤트가 발생했습니다:</p>
      <p><strong>${context.alertType}</strong></p>
      <p>자세한 내용을 확인하고 필요한 조치를 취하세요.</p>
    `;
	}

	private getDefaultTemplate(context: Record<string, any>): string {
		return `
      <h1>알림</h1>
      <p>시스템에서 보내는 알림입니다.</p>
      <pre>${JSON.stringify(context, null, 2)}</pre>
    `;
	}
}

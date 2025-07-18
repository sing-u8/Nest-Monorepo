import { databaseConfig, databaseConfigKeys } from "@config/database.config";
import { envValidationSchema, envVariableKeys } from "@config/env.validation";
import { jwtConfig, jwtConfigKeys, jwtModuleConfig } from "@config/jwt.config";
import { Logger, Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { EventEmitterModule } from "@nestjs/event-emitter";
import { JwtModule } from "@nestjs/jwt";
import { TypeOrmModule } from "@nestjs/typeorm";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { AuthModule } from "./auth/auth.module";

@Module({
	imports: [
		ConfigModule.forRoot({
			isGlobal: true,
			cache: true,
			validationSchema: envValidationSchema,
			validationOptions: {
				allowUnknown: true,
				abortEarly: true,
			},
			load: [databaseConfig, jwtConfig, jwtModuleConfig],
		}),

		TypeOrmModule.forRootAsync({
			inject: [ConfigService],
			useFactory: (configService: ConfigService) => {
				return configService.get(databaseConfigKeys.database);
			},
		}),

		JwtModule.registerAsync({
			global: true,
			inject: [ConfigService],
			useFactory: (configService: ConfigService) => {
				return configService.get(jwtConfigKeys.jwtModule);
			},
		}),

		EventEmitterModule.forRoot({
			wildcard: false,
			delimiter: ".",
			newListener: false,
			removeListener: false,
			maxListeners: 10,
			verboseMemoryLeak: false,
			ignoreErrors: false,
		}),

		// 도메인 모듈
		AuthModule,
	],
	controllers: [AppController],
	providers: [AppService],
})
export class AppModule {
	constructor(private readonly configService: ConfigService) {
		if (process.env.NODE_ENV === envVariableKeys.NODE_ENV.development) {
			Logger.log("🚀 Auth-Service Application Starting...");
			Logger.log(
				`📊 Database: ${this.configService.get(envVariableKeys.DATABASE_HOST)}:${this.configService.get("DATABASE_PORT")}`,
			);
			Logger.log(
				`🔐 JWT Secret: ${this.configService.get(envVariableKeys.JWT_SECRET) ? "✅ Set" : "❌ Not Set"}`,
			);
			Logger.log(
				`🌐 Port: ${this.configService.get(envVariableKeys.PORT, 3000)}`,
			);
		}
	}
}

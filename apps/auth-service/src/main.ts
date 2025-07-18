/**
 * This is not a production server yet!
 * This is only a minimal backend to get started.
 */

import { envVariableKeys } from "@config/env.validation";
import { Logger, ValidationPipe } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";

async function bootstrap() {
	const app = await NestFactory.create(AppModule);
	const configService: ConfigService = app.get(ConfigService);

	app.useGlobalPipes(
		new ValidationPipe({
			whitelist: true,
			forbidNonWhitelisted: true,
			transform: true,
			validateCustomDecorators: true,
			disableErrorMessages: true, // Set to false for development to see detailed error messages
		}),
	);

	app.enableCors({
		origin:
			process.env.NODE_ENV === envVariableKeys.NODE_ENV.development
				? ["http://localhost:3000", "http://localhost:3001"]
				: [], // set real production origins here
		credentials: true,
		methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
		allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
	});

	const globalPrefix = "api";
	app.setGlobalPrefix(globalPrefix, {
		exclude: ["health", "docs", "status"],
	});

	app.enableShutdownHooks();

	const port = configService.get<number>(envVariableKeys.PORT, 3000);
	await app.listen(port);

	console.log(`🚀 Application is running on: http://localhost:${port}`);
	console.log(`📚 API endpoints available at: http://localhost:${port}/api`);

	if (process.env.NODE_ENV === "development") {
		console.log("🔧 Development mode - Auto-reload enabled");
		console.log(
			`📖 Swagger documentation will be available at: http://localhost:${port}/api/docs`,
		);
	}

	return app;
}

bootstrap().catch((error) => {
	Logger.error("Error during application bootstrap", error);
	process.exit(1);
});

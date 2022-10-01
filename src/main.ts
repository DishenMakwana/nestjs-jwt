import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(new ValidationPipe());

  // same thing define in app.module.ts file
  // const reflector = new Reflector();
  // app.useGlobalGuards(new AtGuard(reflector));

  await app.listen(5000);
}
bootstrap();

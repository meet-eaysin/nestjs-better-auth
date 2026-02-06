import { Module } from '@nestjs/common';
import { AuthModule } from './auth-module.ts';
import { auth } from './auth.ts';
import { AppController } from './app.controller.ts';

@Module({
  imports: [
    AuthModule.forRoot({ 
      auth,
      disableGlobalAuthGuard: false 
    })
  ],
  controllers: [AppController]
})
export class AppModule {}

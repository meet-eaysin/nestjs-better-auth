import { Module } from '@nestjs/common';
import { AuthModule } from './auth-module.js';
import { auth } from './auth.js';
import { AppController } from './app.controller.js';

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

import { Controller, Get } from '@nestjs/common';
import { Session, UserSession, Public, AllowAnonymous } from './index.js';

@Controller()
export class AppController {
  @AllowAnonymous()
  @Get()
  getHello() {
    return { 
        message: "NestJS Better Auth Demo is Running!",
        endpoints: [
            "/api/auth/session",
            "/protected"
        ]
    };
  }

  @AllowAnonymous()
  @Get('protected')
  getProtected(@Session() session: UserSession) {
    return {
        message: "You are authenticated (or this is public)!",
        session: session || "No session found"
    };
  }
}


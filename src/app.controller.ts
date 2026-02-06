import { Controller, Get } from '@nestjs/common';
import { Session, UserSession } from './index.js';

@Controller()
export class AppController {
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

  @Get('protected')
  getProtected(@Session() session: UserSession) {
    return {
        message: "You are authenticated!",
        session: session || "No session found"
    };
  }
}

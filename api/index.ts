import "reflect-metadata";
import { NestFactory } from '@nestjs/core';
import { ExpressAdapter } from '@nestjs/platform-express';
import { AppModule } from '../src/app.module.js';
import express from 'express';

const server = express();
server.set('trust proxy', true);

let cachedApp: any;

export default async (req: any, res: any) => {
  console.log(`[DEBUG] Vercel Request: ${req.method} ${req.url}`);
  if (!cachedApp) {
    console.log('[DEBUG] Initializing cached NestJS application...');
    const app = await NestFactory.create(
      AppModule,
      new ExpressAdapter(server),
      { bodyParser: false }
    );
    
    app.enableCors({
      origin: '*',
      credentials: true,
    });

    await app.init();
    cachedApp = server;
  }
  
  cachedApp(req, res);
};

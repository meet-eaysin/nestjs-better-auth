import "reflect-metadata";
import { NestFactory } from '@nestjs/core';
import { ExpressAdapter } from '@nestjs/platform-express';
import { AppModule } from '../src/app.module.js';
import express from 'express';

const server = express();

let cachedApp: any;

export default async (req: any, res: any) => {
  if (!cachedApp) {
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

import "reflect-metadata";
import { NestFactory } from '@nestjs/core';
import { ExpressAdapter } from '@nestjs/platform-express';
import { AppModule } from '../src/app.module.js';
import express from 'express';

const server = express();

export default async (req: any, res: any) => {
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
  server(req, res);
};

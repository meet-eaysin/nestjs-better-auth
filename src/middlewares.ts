import type { NextFunction, Request, Response } from "express";
import * as express from "express";

export function SkipBodyParsingMiddleware(basePath = "/api/auth") {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.baseUrl.startsWith(basePath)) {
      return next();
    }

    express.json()(req, res, (err) => {
      if (err) return next(err);
      express.urlencoded({ extended: true })(req, res, next);
    });
  };
}

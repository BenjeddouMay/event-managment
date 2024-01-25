import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AdminAuthMiddleware implements NestMiddleware {
  constructor(private jwtService: JwtService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new UnauthorizedException('Admin authorization token is missing.');
    }

    const token = authHeader.split(' ')[1];
    try {
      const decoded = this.jwtService.verify(token);
      if (decoded.role !== 'admin') {
        throw new UnauthorizedException('Access denied.');
      }

      // Ajouter les informations de l'admin à la requête
      req['admin'] = decoded; // Vous pouvez utiliser une interface appropriée pour 'admin'

      next();
    } catch (error) {
      throw new UnauthorizedException('Invalid token.');
    }
  }
}

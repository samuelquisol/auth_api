import {
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { Logger } from '@nestjs/common';

@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(AtGuard.name);

  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride('IsPublic', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) return Promise.resolve(true);

    return super.canActivate(context) as Promise<boolean>;
  }

  handleRequest(err, user, info: Error) {
    if (err || info) {
      this.logger.error(`JWT error: ${info.message || err}`);
      throw new HttpException('Token is expired!', HttpStatus.UNAUTHORIZED);
    }

    if (!user) {
      this.logger.warn('Access Denied: Unauthorized access attempt');
      throw new UnauthorizedException('Access Denied.');
    }

    return user;
  }
}

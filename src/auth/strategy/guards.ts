import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}

@Injectable()
export class AccessTokenAuthGuard extends AuthGuard('jwt-access-token') {}

@Injectable()
export class RefreshTokenAuthGuard extends AuthGuard('jwt-refresh-token') {}

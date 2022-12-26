import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AccessTokenAuthGuard extends AuthGuard('jwt') {}


@Injectable()
export class RefreshTokenAuthGuard extends AuthGuard('jwt-refresh') {}
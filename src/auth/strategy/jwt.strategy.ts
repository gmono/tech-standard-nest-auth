import { ObjectLiteral } from 'typeorm';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Inject, Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { EXTRA_OPTIONS } from '../symbols';
import { Request } from 'express';
import { AuthModuleExtraOptions, JwtOptions } from '../types';

@Injectable()
export class JwtAccessTokenStrategy<Entity extends ObjectLiteral, JwtPayload extends ObjectLiteral> extends PassportStrategy(Strategy) {
  constructor(
    private authService: AuthService<Entity>,
    @Inject(EXTRA_OPTIONS) public options: AuthModuleExtraOptions,
  ) {
    super({
      ignoreExpiration: false,
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: options.jwt.accessTokenSecretOrKey,
    });
  }

  async validate(payload: JwtPayload) {
    return this.authService.userService.jwtValidator(payload);                                              // Otherwise, use the default validation.
  }
}

@Injectable()
export class JwtRefreshTokenStrategy<Entity extends ObjectLiteral, JwtPayload extends ObjectLiteral> extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    @Inject(EXTRA_OPTIONS) public options: AuthModuleExtraOptions,
  ) {
    super({
      passReqToCallback: true,
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: options.jwt.refreshTokenSecretOrKey || options.jwt.accessTokenSecretOrKey,
    });
  }

  validate(req: Request, payload: JwtPayload) {
    const refreshToken = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
    return { ...payload, refreshToken };
  }
}

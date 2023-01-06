import passport = require('passport');
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { ExtractJwt, JwtFromRequestFunction } from 'passport-jwt';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { DataSource, EntityTarget, ObjectLiteral, Repository } from 'typeorm';
import { getStrategyError, getTokenExpiresIn } from './helpers';
import { BaseUserService } from './baseuser.service';
import {
  AuthModuleExtraOptions,
  AUTH_OPTIONS,
  UserAuthServiceType,
  USER_ENTITY,
  USER_SERVICE,
} from './types';

@Injectable()
export class AuthService<
  Entity extends ObjectLiteral = ObjectLiteral,
  JwtPayload extends ObjectLiteral = ObjectLiteral,
  RegisterDTO extends ObjectLiteral = ObjectLiteral,
> {
  private userRepository: Repository<Entity>;
  passport: passport.Authenticator;

  constructor(
    private jwtService: JwtService,
    private dataSource: DataSource,
    @Inject(USER_ENTITY) private userEntity: EntityTarget<Entity>,
    @Inject(USER_SERVICE)
    public userService: UserAuthServiceType<Entity, JwtPayload, RegisterDTO>,
    @Inject(AUTH_OPTIONS) private opts: AuthModuleExtraOptions,
  ) {
    this.userRepository = this.userEntity
      ? this.dataSource.getRepository(this.userEntity)
      : null;
    if (this.userService.constructor.name === 'UseDefaultUserService') {
      this.userService = new BaseUserService(this.userRepository, opts);
    }

    if (opts.passportStrategies) {
      if (
        this.userService.onBeforePassportAuthenticateResponse ===
        BaseUserService.prototype.onBeforePassportAuthenticateResponse
      ) {
        throw new Error(
          'onBeforePassportAuthenticateResponse must be implemented in your custom user service when using passport strategies',
        );
      }
      this.passport = new passport.Passport();
      for (const strategy of opts.passportStrategies) {
        this.passport.use(strategy);
        this.passport.serializeUser((user, cb) =>
          process.nextTick(() => cb(null, user)),
        );
        this.passport.deserializeUser((user, cb) =>
          process.nextTick(() => cb(null, user)),
        );
      }
    }
  }

  passportAuthenticate(providerName: string, req: Request, res: Response) {
    this.passport.authenticate(providerName)(req, res);
  }

  async passportAuthenticateCallback(
    providerName: string,
    req: Request,
  ): Promise<{
    err: Error;
    rawErr: any;
    user: any;
    info: any;
    status: any;
  }> {
    return new Promise((resolve) => {
      this.passport.authenticate(
        providerName,
        { session: false },
        (rawErr, user, info, status) => {
          resolve({
            rawErr,
            user,
            info,
            status,
            err: getStrategyError(rawErr, user, info, status),
          });
        },
      )(req);
    });
  }

  jwtExtractor(): JwtFromRequestFunction {
    return this.opts.jwt.jwtFromRequest
      ? this.opts.jwt.jwtFromRequest()
      : ExtractJwt.fromAuthHeaderAsBearerToken();
  }

  async getLoginTokens(user: Entity) {
    const [refreshTokenPayload, accessTokenPayload] = await Promise.all([
      this.userService.createJwtRefreshTokenPayload(user),
      this.userService.createJwtAccessTokenPayload(user),
    ]);

    const [refreshToken, accessToken] = await Promise.all([
      this.jwtService.signAsync(refreshTokenPayload, {
        ...(this.opts.jwt.refresh || {}),
      }),
      this.jwtService.signAsync(accessTokenPayload),
    ]);

    return {
      refreshToken,
      accessToken,
      refreshTokenExpiresAt: getTokenExpiresIn(refreshToken),
      accessTokenExpiresAt: getTokenExpiresIn(accessToken),
    };
  }

  async refreshToken(payload: JwtPayload) {
    const user = await this.userService.jwtValidator(payload);
    if (!user) {
      throw new UnauthorizedException();
    }

    const tokenPromises = [
      this.jwtService.signAsync(
        await this.userService.createJwtAccessTokenPayload(user),
      ),
    ];

    if (this.opts.enableRefreshTokenRotation) {
      tokenPromises.push(
        this.jwtService.signAsync(
          await this.userService.createJwtRefreshTokenPayload(user),
          { ...(this.opts.jwt.refresh || {}) },
        ),
      );
    }

    const [accessToken, refreshToken] = await Promise.all(tokenPromises);

    return { user, accessToken, refreshToken };
  }
}

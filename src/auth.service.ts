import passport = require('passport');
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { ExtractJwt, JwtFromRequestFunction } from 'passport-jwt';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { DataSource, EntityTarget, ObjectLiteral, Repository } from 'typeorm';
import { getStrategyError, getTokenExpiresIn } from './helpers';
import { BaseUserService } from './baseuser.service';
import {
  AuthModuleConfig,
  AUTH_CONFIG,
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
    @Inject(AUTH_CONFIG) private opts: AuthModuleConfig,
  ) {
    this.userRepository = this.userEntity
      ? this.dataSource.getRepository(this.userEntity)
      : null;
    if (this.userService.constructor.name === 'UseDefaultUserService') {
      this.userService = new BaseUserService(this.userRepository, opts);
    }

    if (opts.passportStrategies && opts.passportStrategies.length) {
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

  async getUserFromAccessTokenOrVerifyToken(
    accessToken?: string,
    token?: string,
    ignoreExpiration?: boolean,
  ): Promise<Entity> {
    let user: Entity;
    if (accessToken) {
      let payload: JwtPayload;
      try {
        payload = this.jwtService.verify(accessToken, {
          ...(this.opts.jwt.refresh || {}),
          ignoreExpiration,
        });
      } catch (e) {
        throw new UnauthorizedException();
      }

      user = await this.userService.jwtValidator(payload);
    }

    if (token) {
      const { user: userFromToken } = await this.userService.verifyToken(token, ignoreExpiration);
      user = userFromToken;
    }

    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
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

  async refreshToken(refresh_token: string) {
    if (!refresh_token) {
      throw new UnauthorizedException('Refresh token is required');
    }

    let payload: JwtPayload;
    try {
      payload = this.jwtService.verify(refresh_token, {
        ...(this.opts.jwt.refresh || {}),
        ignoreExpiration: false,
      });
    } catch (e) {
      throw new UnauthorizedException();
    }

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

    return {
      user,
      accessToken,
      refreshToken: refreshToken || refresh_token,
      refreshTokenExpiresAt: getTokenExpiresIn(refreshToken || refresh_token),
      accessTokenExpiresAt: getTokenExpiresIn(accessToken)
    };
  }
}

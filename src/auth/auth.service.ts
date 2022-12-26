import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { DataSource, EntityTarget, ObjectLiteral, Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { AuthModuleExtraOptions, UserAuthServiceType } from './types';
import { EXTRA_OPTIONS, USER_ENTITY, USER_SERVICE } from './symbols';
import { BaseUserService } from './user.service';

@Injectable()
export class AuthService<
  Entity extends ObjectLiteral = ObjectLiteral,
  JwtPayload extends ObjectLiteral = ObjectLiteral,
  RegisterDTO extends ObjectLiteral = ObjectLiteral,
> {
  private userRepository: Repository<Entity>;

  constructor(
    private jwtService: JwtService,
    private dataSource: DataSource,
    @Inject(USER_SERVICE) public userService: UserAuthServiceType<Entity, JwtPayload, RegisterDTO>,
    @Inject(USER_ENTITY) private userEntity: EntityTarget<Entity>,
    @Inject(EXTRA_OPTIONS) private options: AuthModuleExtraOptions,
  ) {
    this.userRepository = this.dataSource.getRepository(this.userEntity);
    if (this.userService.constructor.name === 'UseDefaultUserService') {
      this.userService = new BaseUserService(this.userRepository, options);
    }
  }

  async getLoginTokens(user: Entity) {
    const [accessTokenPayload, refreshTokenPayload] = await Promise.all([
      this.userService.createJwtAccessTokenPayload(user),
      this.userService.createJwtRefreshTokenPayload(user),
    ]);

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        accessTokenPayload,
        {
          secret: this.options.jwt.accessTokenSecretOrKey,
          expiresIn: this.options.jwt.accessTokenExpiresIn,
        },
      ),
      this.jwtService.signAsync(
        refreshTokenPayload,
        {
          secret: this.options.jwt.refreshTokenSecretOrKey || this.options.jwt.accessTokenSecretOrKey,
          expiresIn: this.options.jwt.refreshTokenExpiresIn || '7d',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshToken(payload: JwtPayload) {
    const user = await this.userService.jwtValidator(payload);
    if (!user) {
      throw new UnauthorizedException();
    }

    const tokenPromises = [this.jwtService.signAsync(
      await this.userService.createJwtAccessTokenPayload(user),
      {
        secret: this.options.jwt.accessTokenSecretOrKey,
        expiresIn: this.options.jwt.accessTokenExpiresIn,
      },
    )];

    if (this.options.enableRefreshTokenRotation) {
      tokenPromises.push(this.jwtService.signAsync(
        await this.userService.createJwtRefreshTokenPayload(user),
        {
          secret: this.options.jwt.refreshTokenSecretOrKey || this.options.jwt.accessTokenSecretOrKey,
          expiresIn: this.options.jwt.refreshTokenExpiresIn || '7d',
        },
      ));
    }

    const [accessToken, refreshToken] = await Promise.all(tokenPromises);

    return { user, accessToken, refreshToken };
  }
}

import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import {
  AuthModuleExtraOptions,
  AUTH_OPTIONS,
  JwtPayload,
  PassportCallbackData,
} from 'src/auth/types';
import { BaseUserService } from 'src/auth/baseuser.service';
import { DataSource, Repository } from 'typeorm';
import { JwtPayloadSub } from './types';
import { UserEntity } from './user.entity';

@Injectable()
export class CustomUserService extends BaseUserService<
  UserEntity,
  JwtPayloadSub
> {
  constructor(
    @InjectRepository(UserEntity) userRepository: Repository<UserEntity>,
    @Inject(AUTH_OPTIONS) public options: AuthModuleExtraOptions,
  ) {
    super(userRepository, options);
  }
}

@Injectable()
export class CustomUserServiceWithDataSource extends BaseUserService<
  UserEntity,
  JwtPayloadSub
> {
  constructor(
    private dataSource: DataSource,
    @Inject(AUTH_OPTIONS) public options: AuthModuleExtraOptions,
  ) {
    super(dataSource.getRepository(UserEntity), options);
  }

  // Custom Jwt access token payload, default is { id }
  async createJwtAccessTokenPayload(
    user: UserEntity,
  ): Promise<JwtPayload<JwtPayloadSub>> {
    return {
      sub: user,
    };
  }

  // Custom Jwt refresh token payload, default is { id }
  async createJwtRefreshTokenPayload(
    user: UserEntity,
  ): Promise<JwtPayload<Partial<JwtPayloadSub>>> {
    return {
      sub: {
        id: user.id,
      },
    };
  }

  async onBeforePassportAuthenticateResponse(
    provider: string,
    data: PassportCallbackData,
  ): Promise<any> {
    const { err, user } = data;

    if (err) {
      throw new UnauthorizedException(err.message);
    }

    return {
      refresh_token: user.refreshToken,
      access_token: user.accessToken,
      signin_type: provider,
    };
  }
}

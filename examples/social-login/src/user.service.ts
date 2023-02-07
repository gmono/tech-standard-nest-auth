import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { BaseUserService, AuthModuleConfig, AUTH_CONFIG, PassportCallbackData } from 'tech-standard-nest-auth';
import { DataSource } from 'typeorm';
import { UserEntity } from './user.entity';

@Injectable()
export class CustomUserServiceWithDataSource extends BaseUserService<UserEntity> {
  constructor(
    private dataSource: DataSource,
    @Inject(AUTH_CONFIG) public options: AuthModuleConfig,
  ) {
    super(dataSource.getRepository(UserEntity), options);
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

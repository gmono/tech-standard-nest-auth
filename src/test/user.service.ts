import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { BaseUserService, AuthModuleConfig, AUTH_CONFIG, PassportCallbackData } from '../';
import { Repository } from 'typeorm';
import { UserEntity } from './user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtPayload, UserRegisterDto } from './types';


@Injectable()
export class CustomUserService extends BaseUserService<UserEntity, JwtPayload, UserRegisterDto> {
  constructor(
    @InjectRepository(UserEntity) userRepository: Repository<UserEntity>,
    @Inject(AUTH_CONFIG) public config: AuthModuleConfig,
  ) {
    super(userRepository, config);
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

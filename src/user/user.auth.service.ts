import { Inject, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { EXTRA_OPTIONS } from 'src/auth/symbols';
import { AuthModuleExtraOptions, JwtPayload } from 'src/auth/types';
import { BaseUserService } from 'src/auth/user.service';
import { DataSource, Repository } from 'typeorm';
import { JwtPayloadSub } from './types';
import { UserEntity } from './user.entity';

@Injectable()
export class UserAuthService extends BaseUserService<UserEntity, JwtPayloadSub> {
  constructor(
    @InjectRepository(UserEntity)
    userRepository: Repository<UserEntity>,
    @Inject(EXTRA_OPTIONS) public options: AuthModuleExtraOptions,
  ) {
    super(userRepository, options);
  }
}


@Injectable()
export class UserAuthServiceWithDataSource extends BaseUserService<UserEntity, JwtPayloadSub> {
  constructor(
    private dataSource: DataSource,
    @Inject(EXTRA_OPTIONS) public options: AuthModuleExtraOptions,
  ) {
    super(dataSource.getRepository(UserEntity), options);
  }

   // Custom Jwt access token payload, default is { id }
   async createJwtAccessTokenPayload(user: UserEntity): Promise<JwtPayload<JwtPayloadSub>> {
    return {
      sub: user,
    };
  }

  // Custom Jwt refresh token payload, default is { id }
  async createJwtRefreshTokenPayload(user: UserEntity): Promise<JwtPayload<Partial<JwtPayloadSub>>> {
    return {
      sub: {
        id: user.id,
      },
    };
  }
}

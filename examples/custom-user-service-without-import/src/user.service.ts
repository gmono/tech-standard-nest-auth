import { Inject, Injectable } from '@nestjs/common';
import { BaseUserService, AuthModuleConfig, AUTH_CONFIG } from '@tech-standard-nest-auth';
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
}

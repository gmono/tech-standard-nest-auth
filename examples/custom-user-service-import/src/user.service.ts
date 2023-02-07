import { Inject, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { BaseUserService, AuthModuleConfig, AUTH_CONFIG } from 'tech-standard-nest-auth';
import { Repository } from 'typeorm';
import { UserEntity } from './user.entity';

@Injectable()
export class CustomUserService extends BaseUserService<UserEntity> {
  constructor(
    @InjectRepository(UserEntity) userRepository: Repository<UserEntity>,
    @Inject(AUTH_CONFIG) public config: AuthModuleConfig,
  ) {
    super(userRepository, config);
  }
}

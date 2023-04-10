import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PassportModule } from '@nestjs/passport';
import { DynamicModule, Global, Module, Type } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import {
  JwtAccessTokenStrategy,
  JwtRefreshTokenStrategy,
  LocalStrategy,
} from './strategy/strategies';
import {
  AuthModuleOptions,
  AUTH_CONFIG,
  UserAuthServiceType,
  USER_ENTITY,
  USER_SERVICE,
} from './types';
import { EntityClassOrSchema } from '@nestjs/typeorm/dist/interfaces/entity-class-or-schema.type';
import { getOptions } from './helpers';
import { ObjectLiteral } from 'typeorm';

@Module({})
@Global()
export class AuthModule {
  static register<
    Entity extends ObjectLiteral = ObjectLiteral,
    JwtPayload extends ObjectLiteral = ObjectLiteral,
    RegisterDTO extends ObjectLiteral = ObjectLiteral,
  >(opts: AuthModuleOptions<Entity, JwtPayload, RegisterDTO>): DynamicModule {
    if (opts.authKey.length < 32) {
      throw new Error('authKey must be at least 32 characters long');
    }

    opts = getOptions(opts);
    const { typeormUserEntity, userService, config, imports } = opts;
    const UserServiceClass =
      (userService as unknown as Type<
        UserAuthServiceType<Entity, JwtPayload, RegisterDTO>
      >) || class UseDefaultUserService {};
    return {
      module: AuthModule,
      imports: [
        PassportModule,
        JwtModule.register(config.jwt),
        typeormUserEntity
          ? TypeOrmModule.forFeature([typeormUserEntity as EntityClassOrSchema])
          : null,
        ...(imports || []),
      ].filter((i) => !!i),
      providers: [
        {
          provide: USER_ENTITY,
          useValue: typeormUserEntity || null,
        },
        {
          provide: USER_SERVICE,
          useClass: UserServiceClass,
        },
        {
          provide: AUTH_CONFIG,
          useValue: config,
        },
        UserServiceClass,
        AuthService<Entity, JwtPayload, RegisterDTO>,
        JwtAccessTokenStrategy<Entity, JwtPayload>,
        JwtRefreshTokenStrategy<Entity, JwtPayload>,
        LocalStrategy<Entity>,
      ],
      exports: [AuthService, USER_SERVICE, AUTH_CONFIG],
      controllers: opts.disableRouter ? [] : [AuthController],
    };
  }
}

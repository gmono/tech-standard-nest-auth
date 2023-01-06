import { JwtModule } from '@nestjs/jwt';
import { ObjectLiteral } from 'typeorm';
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
  AUTH_OPTIONS,
  UserAuthServiceType,
  USER_ENTITY,
  USER_SERVICE,
} from './types';
import { EntityClassOrSchema } from '@nestjs/typeorm/dist/interfaces/entity-class-or-schema.type';

@Module({})
@Global()
export class AuthModule {
  static register<
    Entity extends ObjectLiteral = ObjectLiteral,
    JwtPayload extends ObjectLiteral = ObjectLiteral,
    RegisterDTO extends ObjectLiteral = ObjectLiteral,
  >(opts: AuthModuleOptions<Entity, JwtPayload>): DynamicModule {
    const { typeormUserEntity, userService, options, imports } = opts;
    const UserServiceClass =
      (userService as unknown as Type<
        UserAuthServiceType<Entity, JwtPayload, RegisterDTO>
      >) || class UseDefaultUserService {};
    const jwtOptions = {
      signOptions: {
        expiresIn: '900s',
      },
      ...(options.jwt || {}),
    };
    return {
      module: AuthModule,
      imports: [
        PassportModule,
        JwtModule.register(jwtOptions),
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
          provide: AUTH_OPTIONS,
          useValue: options,
        },
        UserServiceClass,
        AuthService<Entity, JwtPayload, RegisterDTO>,
        JwtAccessTokenStrategy<Entity, JwtPayload>,
        JwtRefreshTokenStrategy<Entity, JwtPayload>,
        LocalStrategy<Entity>,
      ],
      exports: [AuthService, USER_SERVICE],
      controllers: opts.options.disableApi ? [] : [AuthController],
    };
  }
}

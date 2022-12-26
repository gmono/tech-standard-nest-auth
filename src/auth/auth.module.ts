import { DynamicModule, Module, Type } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { LocalStrategy } from './strategy/local.strategy';
import { JwtAccessTokenStrategy, JwtRefreshTokenStrategy } from './strategy/jwt.strategy';
import { AuthModuleOptions, UserAuthServiceType } from './types';
import { EXTRA_OPTIONS, USER_ENTITY, USER_SERVICE } from './symbols';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EntityClassOrSchema } from '@nestjs/typeorm/dist/interfaces/entity-class-or-schema.type';
import { ObjectLiteral } from 'typeorm';

@Module({})
export class AuthModule {
  static register<
    Entity extends ObjectLiteral = ObjectLiteral,
    JwtPayload extends ObjectLiteral = ObjectLiteral,
    RegisterDTO extends ObjectLiteral = ObjectLiteral,
  >(opts: AuthModuleOptions<Entity, JwtPayload>): DynamicModule {
    const  { typeormUserEntity, userService, options, imports } = opts;
    return {
      module: AuthModule,
      imports: [
        PassportModule,
        JwtModule.register({
          signOptions: { expiresIn: '900s' },
          ...(options.jwt || {}),
        }),
        typeormUserEntity ? TypeOrmModule.forFeature([typeormUserEntity as EntityClassOrSchema]) : null,
        ...(imports || []),
      ].filter(i => !!i),
      providers: [
        {
          provide: USER_ENTITY,
          useValue: typeormUserEntity || null,
        },
        {
          provide: USER_SERVICE,
          useClass: userService as unknown as Type<UserAuthServiceType<Entity, JwtPayload, RegisterDTO>> || class UseDefaultUserService {},
        },
        {
          provide: EXTRA_OPTIONS,
          useValue: options,
        },
        AuthService<Entity, JwtPayload>,
        JwtAccessTokenStrategy<Entity, JwtPayload>,
        JwtRefreshTokenStrategy<Entity, JwtPayload>,
        LocalStrategy<Entity>,
      ],
      exports: [AuthService],
      controllers: [AuthController],
    };
  }
}

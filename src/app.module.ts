import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { AppService } from './app.service';
import { UserEntity } from './user/user.entity';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { AppController } from './app.controller';
import {
  CustomUserService,
  CustomUserServiceWithDataSource,
} from './user/custom.user.service';
import { JwtPayloadSub } from './user/types';
import { passportVerifier } from './auth/helpers';

const authModuleUsageOnlyTypeOrmEntity = {
  typeormUserEntity: UserEntity,
};

const authModuleUsageOnlyServiceWithImport = {
  userService: CustomUserService,
  imports: [TypeOrmModule.forFeature([UserEntity])],
};

const authModuleUsageOnlyServiceWithDataSource = {
  userService: CustomUserServiceWithDataSource,
};

// const authModuleConfig = authModuleUsageOnlyTypeOrmEntity;
// const authModuleConfig = authModuleUsageOnlyServiceWithImport;
const authModuleConfig = authModuleUsageOnlyServiceWithDataSource;

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: 'localhost',
      port: 3306,
      username: 'root',
      password: '123',
      database: 'auth_lib_poc',
      synchronize: true,
      autoLoadEntities: true,
      logging: true,
      entities: [UserEntity],
    }),
    UserModule,
    AuthModule.register<UserEntity, JwtPayloadSub>({
      ...authModuleConfig,
      options: {
        disableApi: false,
        enableRefreshTokenRotation: true,
        passwordHashSecret: 'myPasswordSecret',
        recovery: {
          tokenExpiresIn: 7200,
          tokenSecret: '8b1Rw40iCtys6Lu2W4PuuKKJ7ABuiqBZ',
        },
        jwt: {
          secret: 'appAccessTokenSecret',
          signOptions: {
            expiresIn: '900s',
          },
          refresh: {
            secret: 'appRefreshTokenSecret',
            expiresIn: '7d',
          },
        },
        passportStrategies: [
          new FacebookStrategy(
            {
              clientID: '1141021169942039',
              clientSecret: '0710267b1b904bed35c718e717d8526b',
              callbackURL:
                'http://localhost:3000/social/sign-in/facebook/callback',
            },
            passportVerifier,
          ),
        ],
      },
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {
  constructor(private dataSource: DataSource) {}
}

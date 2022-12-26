import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AppService } from './app.service';
import { UserEntity } from './user/user.entity';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { AppController } from './app.controller';
import { UserAuthService, UserAuthServiceWithDataSource } from './user/user.auth.service';
import { JwtPayloadSub } from './user/types';

const authModuleUsageOnlyTypeOrmEntity = {
  typeormUserEntity: UserEntity,
};

const authModuleUsageOnlyServiceWithImport = {
  userService: UserAuthService,
  imports: [TypeOrmModule.forFeature([UserEntity])],
};

const authModuleUsageOnlyServiceWithDataSource = {
  userService: UserAuthServiceWithDataSource,
};

const authModuleConfig = authModuleUsageOnlyTypeOrmEntity;
// const authModuleConfig = authModuleUsageOnlyServiceWithImport;
// const authModuleConfig = authModuleUsageOnlyServiceWithDataSource;

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
        enableRefreshTokenRotation: true,
        passwordHashSecret: 'myPasswordSecret',
        jwt: {
          accessTokenSecretOrKey: 'myApplicationSecret',
          accessTokenExpiresIn: '20s',
        },
      },
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})

export class AppModule {
  constructor(private dataSource: DataSource) { }
}

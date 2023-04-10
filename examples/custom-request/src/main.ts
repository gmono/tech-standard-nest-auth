import { NestFactory } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EntitySchema, MixedList } from 'typeorm';
import { DynamicModule, Module } from '@nestjs/common';
import { AuthModule } from '@sun-asterisk/nest-auth';
import { UserEntity } from './user.entity';
import { UserController } from './user.controller';
import { JwtPayload, UserRegisterDto } from './types';

export const createTypeOrmMOdule = (entities: MixedList<string | Function | EntitySchema<any>>): DynamicModule => {
  return TypeOrmModule.forRoot({
    type: 'mysql',
    host: 'localhost',
    port: 3306,
    username: 'root',
    password: '123',
    database: 'auth_lib_poc',
    synchronize: true,
    autoLoadEntities: true,
    logging: true,
    entities: entities,
  })
};

@Module({
  imports: [
    createTypeOrmMOdule([UserEntity]),
    AuthModule.register<UserEntity, JwtPayload, UserRegisterDto>({
      disableRouter: true,
      authKey: 'auth_key_with_32_bytes_randomly_',
      typeormUserEntity: UserEntity,
    }),
  ],
  controllers: [UserController],
  providers: [],
})
export class AppModule { }


(async () => (await NestFactory.create(AppModule)).listen(3000))();

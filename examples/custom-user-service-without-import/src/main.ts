import { NestFactory } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EntitySchema, MixedList } from 'typeorm';
import { DynamicModule, Module } from '@nestjs/common';
import { AuthModule } from '@tech-standard-nest-auth';
import { UserEntity } from './user.entity';
import { CustomUserServiceWithDataSource } from './user.service';

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
    logging: false,
    entities: entities,
  })
};

@Module({
  imports: [
    createTypeOrmMOdule([UserEntity]),
    AuthModule.register<UserEntity>({
      authKey: 'auth_key_with_32_bytes_randomly_',
      userService: CustomUserServiceWithDataSource,
    }),
  ],
  controllers: [],
  providers: [],
})
export class AppModule { }


(async () => (await NestFactory.create(AppModule)).listen(3000))();

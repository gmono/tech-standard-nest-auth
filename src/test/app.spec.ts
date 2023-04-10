import { Test } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { UserEntity } from './user.entity';
import { AuthModule } from '../auth.module';
import { UserRegisterDto, JwtPayload } from './types';
import { passportVerifier } from '../helpers';
import { CustomUserService } from './user.service';

const typeOrmModule = TypeOrmModule.forRoot({
  type: 'sqlite',
  database: ':memory:',
  dropSchema: true,
  entities: [UserEntity],
  synchronize: true,
  logging: true,
});

describe('AuthModule', () => {
  it('Should load the module', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        typeOrmModule,
        AuthModule.register<UserEntity, JwtPayload, UserRegisterDto>({
          authKey: 'auth_key_with_32_bytes_randomly_',
          typeormUserEntity: UserEntity,
        }),
      ],
    }).compile();
    expect(moduleRef).toBeDefined();
  });

  it('Should throw error if using password strategies without onBeforePassportAuthenticateResponse', async () => {
    try {
      const moduleRef = await Test.createTestingModule({
        imports: [
          typeOrmModule,
          AuthModule.register<UserEntity, JwtPayload, UserRegisterDto>({
            authKey: 'auth_key_with_32_bytes_randomly_',
            typeormUserEntity: UserEntity,
            config: {
              passportStrategies: [
                new FacebookStrategy(
                  {
                    clientID: 'facebook_client_id',
                    clientSecret: 'facebook_client_secret',
                    callbackURL:
                      'http://localhost:8002/social/sign-in/facebook/callback',
                  },
                  passportVerifier,
                ),
              ],
            }
          }),
        ],
      }).compile();
      expect(moduleRef).toBeDefined();
    } catch (e) {
      expect(e.message).toBe('onBeforePassportAuthenticateResponse must be implemented in your custom user service when using passport strategies');
    }
  });

  it('Should load the module with password strategies and onBeforePassportAuthenticateResponse', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        typeOrmModule,
        AuthModule.register<UserEntity, JwtPayload, UserRegisterDto>({
          authKey: 'auth_key_with_32_bytes_randomly_',
          typeormUserEntity: UserEntity,
          userService: CustomUserService,
          config: {
            passportStrategies: [
              new FacebookStrategy(
                {
                  clientID: 'facebook_client_id',
                  clientSecret: 'facebook_client_secret',
                  callbackURL:
                    'http://localhost:8002/social/sign-in/facebook/callback',
                },
                passportVerifier,
              ),
            ],
          }
        }),
      ],
    }).compile();
    expect(moduleRef).toBeDefined();
  });
});
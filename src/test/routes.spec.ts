import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { Request } from 'express';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HttpServer, INestApplication, UnauthorizedException, UnprocessableEntityException } from '@nestjs/common';
import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { AuthModule } from '../auth.module';
import { UserEntity } from './user.entity';
import { JwtPayload, UserRegisterDto } from './types';
import { createTestUserData, getLoginResponse } from './utils';

describe('AuthRoutes', () => {
  let authController: AuthController;
  let authService: AuthService;
  let app: INestApplication;
  let httpServer: HttpServer;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: 'sqlite',
          database: ':memory:',
          dropSchema: true,
          entities: [UserEntity],
          synchronize: true,
          logging: true,
        }),
        AuthModule.register<UserEntity, JwtPayload, UserRegisterDto>({
          authKey: 'auth_key_with_32_bytes_randomly_',
          typeormUserEntity: UserEntity,
        }),
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    httpServer = app.getHttpServer();
    authService = moduleRef.get<AuthService>(AuthService);
    authController = moduleRef.get<AuthController>(AuthController);
    await app.init();
  });

  it('Register should throw validation error', async () => {
    try {
      await authController.register({})
    } catch (e) {
      expect(e).toBeInstanceOf(UnprocessableEntityException);
      expect(e).toHaveProperty('message', 'Invalid user register data');
    }
  });

  it('Register should success and return user', async () => {
    const { user } = await authController.register(createTestUserData('01'));

    expect(user).toHaveProperty('id', 1);
    expect(user).toHaveProperty('email', 'testuser01@local.ltd');
    expect(user).toHaveProperty('username', 'testuser01');
    expect(user).toHaveProperty('isActive', true);
    expect(user).toHaveProperty('firstName', null);
    expect(user).toHaveProperty('lastName', null);
  });

  it('Register should success throw user because of duplicated data', async () => {
    try {
      await authController.register(createTestUserData('01'));
    } catch (e) {
      expect(e).toBeInstanceOf(UnprocessableEntityException);
      expect(e).toHaveProperty('message', 'User existed');
    }
  });

  it('Confirm token should throw error', async () => {
    try {
      await authController.confirm({ query: {} } as Request)
    } catch (e) {
      expect(e).toBeInstanceOf(UnauthorizedException);
      expect(e).toHaveProperty('message', 'Invalid token');
    }
  });

  it('Confirm token should success', async () => {
    const { token } = await authService.userService.register(createTestUserData('02'));
    const result = await authController.confirm({
      query: {
        token,
      }
    } as unknown as Request);

    expect(result).toHaveProperty('ok', true);
    expect(result).toHaveProperty('type', 'verifyRegister');
  });

  it('Login should throw validation error', async () => {
    const response = await request(httpServer)
      .post('/login')
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('Login should throw invalid user error', async () => {
    const response = await request(httpServer)
      .post('/login')
      .send({
        username: 'testuser01',
        password: 'invalid password',
      })
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('Login should success', async () => {
    const response = await request(httpServer)
      .post('/login')
      .send({
        username: 'testuser01',
        password: 'testuser01',
      })
      .expect(200);
    expect(response.body).toHaveProperty('access_token');
    expect(response.body).toHaveProperty('refresh_token');
    expect(response.body).toHaveProperty('expires_at');
    expect(response.body).toHaveProperty('token_type');
  });

  it('Request Forgot password should throw validation error', async () => {
    const response = await request(httpServer)
      .post('/forgot-password')
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Invalid identity value');
  });

  it('Request Forgot password should throw invalid user error', async () => {
    const response = await request(httpServer)
      .post('/forgot-password')
      .send({
        identity: 'invalid identity',
      })
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('Request Forgot password should success', async () => {
    const response = await request(httpServer)
      .post('/forgot-password')
      .send({
        identity: 'testuser01',
      })
      .expect(200);
    expect(response.body).toHaveProperty('ok', true);
    expect(response.body).toHaveProperty('type', 'forgotPassword');
  });

  it('Request Forgot password service should return token', async () => {
    const { token } = await authService.userService.generateForgotPasswordToken('testuser01@local.ltd');
    expect(token).toBeTruthy();
  });

  it('Confirm Forgot password should throw validation error', async () => {
    const response = await request(httpServer)
      .get('/forgot-password')
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Invalid token');
  });

  it('Confirm Forgot password should throw invalid token error', async () => {
    const response = await request(httpServer)
      .get('/forgot-password?token=invalid_token')
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('Confirm Forgot password should success', async () => {
    const { token } = await authService.userService.generateForgotPasswordToken('testuser01');
    const response = await request(httpServer)
      .get(`/forgot-password?token=${encodeURIComponent(token)}`)
      .expect(200);
    expect(response.body).toHaveProperty('ok', true);
    expect(response.body).toHaveProperty('type', 'verifyForgotPassword');
  });

  /**
   * Reset password
   * Need to process more:
   * - Change password for logged in user
   * - Change password for user with token
   */
  it('ResetPassword without verify token and access token should throw error', async () => {
    const response = await request(httpServer)
      .post('/change-password')
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('ResetPassword.UserForgotPassword with invalid token should throw error', async () => {
    const response = await request(httpServer)
      .post('/change-password')
      .send({
        token: 'invalid_token',
        password: 'new_password',
      })
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('ResetPassword.UserForgotPassword with valid token and no password should throw error', async () => {
    const { token } = await authService.userService.generateForgotPasswordToken('testuser01');
    const response = await request(httpServer)
      .post('/change-password')
      .send({
        token,
      })
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'New password is required');
  });

  it('ResetPassword.UserForgotPassword with valid token and password should success', async () => {
    const { token } = await authService.userService.generateForgotPasswordToken('testuser01');
    const response = await request(httpServer)
      .post('/change-password')
      .send({
        token,
        password: 'new_password',
      })
      .expect(200);
    expect(response.body).toHaveProperty('ok', true);
    expect(response.body).toHaveProperty('type', 'changePassword');

    const loginResponse = await getLoginResponse(httpServer, {
      username: 'testuser01',
      password: 'new_password',
    });

    expect(loginResponse).toHaveProperty('access_token');
    expect(loginResponse).toHaveProperty('refresh_token');
    expect(loginResponse).toHaveProperty('expires_at');
    expect(loginResponse).toHaveProperty('token_type');
  });

  it('ResetPassword.UserChangePassword with invalid access token should throw error', async () => {
    const response = await request(httpServer)
      .post('/change-password')
      .set('Authorization', 'Bearer invalid_token')
      .send()
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('ResetPassword.UserChangePassword with valid access token and no password should throw error', async () => {
    const { access_token } = await getLoginResponse(httpServer, {
      username: 'testuser01',
      password: 'new_password',
    });
    const response = await request(httpServer)
      .post('/change-password')
      .set('Authorization', `Bearer ${access_token}`)
      .send()
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'New password is required');
  });

  it('ResetPassword.UserChangePassword with valid access token and password and no old_password should throw error', async () => {
    const { access_token } = await getLoginResponse(httpServer, {
      username: 'testuser01',
      password: 'new_password',
    });

    const response = await request(httpServer)
      .post('/change-password')
      .set('Authorization', `Bearer ${access_token}`)
      .send({
        password: 'new_password2',
      })
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Old password is required');
  });

  it('ResetPassword.UserChangePassword with valid access token and password and invalid old_password should throw error', async () => {
    const { access_token } = await getLoginResponse(httpServer, {
      username: 'testuser01',
      password: 'new_password',
    });

    const response = await request(httpServer)
      .post('/change-password')
      .set('Authorization', `Bearer ${access_token}`)
      .send({
        password: 'new_password2',
        old_password: 'invalid_password',
      })
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Old password is incorrect');
  });

  it('ResetPassword.UserChangePassword with valid access token and password and valid old_password should success', async () => {
    const { access_token } = await getLoginResponse(httpServer, {
      username: 'testuser01',
      password: 'new_password',
    });

    const response = await request(httpServer)
      .post('/change-password')
      .set('Authorization', `Bearer ${access_token}`)
      .send({
        password: 'new_password2',
        old_password: 'new_password',
      })
      .expect(200);
    expect(response.body).toHaveProperty('ok', true);

    const { access_token: accessToken } = await getLoginResponse(httpServer, {
      username: 'testuser01',
      password: 'new_password2',
    });

    expect(accessToken).toBeTruthy();
  });

  it('logout without access token should throw error', async () => {
    const response = await request(httpServer)
      .post('/logout')
      .send()
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('logout with invalid access token should throw error', async () => {
    const response = await request(httpServer)
      .post('/logout')
      .set('Authorization', `Bearer invalid_token`)
      .send()
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('logout with valid access token should success', async () => {
    const { access_token } = await getLoginResponse(httpServer, {
      username: 'testuser01',
      password: 'new_password2',
    });

    await request(httpServer)
      .post('/logout')
      .set('Authorization', `Bearer ${access_token}`)
      .send()
      .expect(200);
  });

  it('refresh token without refresh token should throw error', async () => {
    const response = await request(httpServer)
      .post('/refresh')
      .send()
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Refresh token is required');
  });

  it('refresh token with invalid refresh token should throw error', async () => {
    const response = await request(httpServer)
      .post('/refresh')
      .send({
        refresh_token: 'invalid_token',
      })
      .expect(401);
    expect(response.body).toHaveProperty('statusCode', 401);
    expect(response.body).toHaveProperty('message', 'Unauthorized');
  });

  it('refresh token with valid refresh token should success', async () => {
    const { refresh_token } = await getLoginResponse(httpServer, {
      username: 'testuser01',
      password: 'new_password2',
    });

    const response = await request(httpServer)
      .post('/refresh')
      .send({
        refresh_token,
      })
      .expect(200);
    expect(response.body).toHaveProperty('access_token');
    expect(response.body).toHaveProperty('refresh_token');
    expect(response.body).toHaveProperty('expires_at');
    expect(response.body).toHaveProperty('token_type');
  });
});

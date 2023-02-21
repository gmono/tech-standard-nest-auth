import { Request, Response } from 'express';
import {
  Controller,
  Post,
  UseGuards,
  Get,
  Body,
  Req,
  Res,
} from '@nestjs/common';
import {
  AccessTokenAuthGuard,
  LocalAuthGuard,
} from './strategy/guards';
import { AuthService } from './auth.service';

@Controller('')
export class AuthController {
  constructor(private authService: AuthService) { }

  @Post('/register')
  async register(@Body() body) {
    const { user, token } = await this.authService.userService.register(body);
    return await this.authService.userService.onBeforeRegisterResponse(
      body,
      token,
      user,
    );
  }

  @Get('/confirm')
  async confirm(@Req() req: Request) {
    const token = req.query.token as string;
    const { user, createdAt } =
      await this.authService.userService.verifyToken(token);
    return await this.authService.userService.onBeforeVerifyRegisterResponse(
      user,
      token,
      createdAt,
    );
  }

  @UseGuards(LocalAuthGuard)
  @Post('/login')
  async login(@Req() req: Request) {
    const {
      refreshToken,
      accessToken,
      refreshTokenExpiresAt,
      accessTokenExpiresAt,
    } = await this.authService.getLoginTokens(req.user);
    return await this.authService.userService.onBeforeLoginResponse(
      req.user,
      refreshToken,
      accessToken,
      refreshTokenExpiresAt,
      accessTokenExpiresAt,
    );
  }

  @Post('/forgot-password')
  async forgotPassword(@Body() body) {
    const { user, token } =
      await this.authService.userService.generateForgotPasswordToken(
        body.email,
      );
    console.log({ token });
    return await this.authService.userService.onBeforeForgotPasswordResponse(
      user,
      token,
    );
  }

  @Get('/forgot-password')
  async verifyForgotPaswordToken(@Req() req: Request) {
    const token = req.query.token as string;
    const { user, createdAt } =
      await this.authService.userService.verifyToken(token);
    return await this.authService.userService.onBeforeVerifyForgotPasswordResponse(
      user,
      token,
      createdAt,
    );
  }

  @Post('/change-password')
  async changePassword(@Body() body) {
    const { old_password, password, token } = body;
    const { user } = await this.authService.userService.verifyToken(token, true);

    const result = await this.authService.userService.changePassword(user, old_password, password);
    return await this.authService.userService.onBeforeChangePasswordResponse(
      user,
      old_password,
      password,
      result,
    );
  }

  @UseGuards(AccessTokenAuthGuard)
  @Get('logout')
  async logout(@Req() req: Request) {
    const accessToken = this.authService.jwtExtractor()(req);
    return await this.authService.userService.onBeforeLogoutResponse(
      accessToken,
    );
  }

  @Post('refresh')
  async refreshTokens(@Body() body, @Req() req: Request) {
    const { refresh_token } = body;
    if (!refresh_token) {
      throw new Error('Refresh token is required');
    }
    const { user, accessToken, refreshToken, refreshTokenExpiresAt, accessTokenExpiresAt } =
      await this.authService.refreshToken(refresh_token);
    return await this.authService.userService.onBeforeRefreshTokenResponse(
      user,
      refreshToken,
      accessToken,
      refreshTokenExpiresAt,
      accessTokenExpiresAt,
    );
  }

  @Get('/social/sign-in/:provider')
  async passportAuthenticate(@Req() req: Request, @Res() res: Response) {
    return this.authService.passportAuthenticate(req.params.provider, req, res);
  }

  @Get('/social/sign-in/:provider/callback')
  async passportAuthenticateCallback(@Req() req: Request) {
    const result = await this.authService.passportAuthenticateCallback(
      req.params.provider,
      req,
    );
    return await this.authService.userService.onBeforePassportAuthenticateResponse(
      req.params.provider,
      result,
    );
  }

  @UseGuards(AccessTokenAuthGuard)
  @Get('/me')
  me(@Req() req: Request) {
    return req.user;
  }
}

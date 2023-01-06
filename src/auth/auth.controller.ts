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
import { AuthService } from './auth.service';
import {
  AccessTokenAuthGuard,
  RefreshTokenAuthGuard,
  LocalAuthGuard,
} from './strategy/guards';

@Controller('')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/register')
  async register(@Body() body) {
    const user = await this.authService.userService.register(body);
    return await this.authService.userService.onBeforeRegisterResponse(
      body,
      user,
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
      await this.authService.userService.generateforgotPasswordToken(
        body.email,
      );
    return await this.authService.userService.onBeforeForgotPasswordResponse(
      user,
      token,
    );
  }

  @Get('/forgot-password')
  async verifyForgotPaswordToken(@Req() req: Request) {
    const token = req.query.token as string;
    const { user, createdAt } =
      await this.authService.userService.verifyforgotPasswordToken(token);
    return await this.authService.userService.onBeforeVerifyForgotPasswordResponse(
      user,
      token,
      createdAt,
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

  @UseGuards(RefreshTokenAuthGuard)
  @Get('refresh')
  async refreshTokens(@Req() req: Request) {
    const { user, accessToken, refreshToken } =
      await this.authService.refreshToken(req.user);
    return await this.authService.userService.onBeforeRefreshTokenResponse(
      req.user,
      user,
      refreshToken,
      accessToken,
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

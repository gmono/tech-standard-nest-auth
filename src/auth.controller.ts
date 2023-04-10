import { Request, Response } from 'express';
import {
  Controller,
  Post,
  UseGuards,
  Get,
  Body,
  Req,
  Res,
  HttpCode,
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

  @HttpCode(200)
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

  @HttpCode(200)
  @Post('/forgot-password')
  async forgotPassword(@Body() body) {
    const { user, token } =
      await this.authService.userService.generateForgotPasswordToken(
        body?.identity,
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
      await this.authService.userService.verifyToken(token);
    return await this.authService.userService.onBeforeVerifyForgotPasswordResponse(
      user,
      token,
      createdAt,
    );
  }

  /**
   * Change password
   * Work in two cases:
   * - Change password for logged in user. Payload:
   *    - new password
   *    - old password,
   *    - access token
   * - Change password for user that forgot password. Payload:
   *    - new password
   *    - verify forgot password token
   * If there is a token --> user is resetting password through the forgot password flow.
   */
  @HttpCode(200)
  @Post('/change-password')
  async changePassword(@Body() body, @Req() req: Request) {
    const { old_password, password, token } = body;
    const accessToken = this.authService.jwtExtractor()(req);
    const user = await this.authService.getUserFromAccessTokenOrVerifyToken(
      accessToken,
      token,
    );

    const isForgot = !!token;
    const result = await this.authService.userService.changePassword(
      user,
      password,
      isForgot,
      old_password,
    );
    return await this.authService.userService.onBeforeChangePasswordResponse(
      user,
      old_password,
      password,
      result,
    );
  }

  @HttpCode(200)
  @UseGuards(AccessTokenAuthGuard)
  @Post('logout')
  async logout(@Req() req: Request) {
    const accessToken = this.authService.jwtExtractor()(req);
    return await this.authService.userService.onBeforeLogoutResponse(
      accessToken,
    );
  }

  @HttpCode(200)
  @Post('refresh')
  async refreshTokens(@Body() body, @Req() req: Request) {
    const { refresh_token } = body;
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

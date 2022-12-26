import { Controller, Post, UseGuards, Get, Body, Req } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { AccessTokenAuthGuard, RefreshTokenAuthGuard } from './strategy/jwt-auth.guard';
import { LocalAuthGuard } from './strategy/local-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) { }

  @Post('/register')
  async register(@Body() body) {
    const user = await this.authService.userService.register(body);
    return await this.authService.userService.onBeforeRegisterResponse(body, user);
  }

  @UseGuards(LocalAuthGuard)
  @Post('/login')
  async login(@Req() req: Request) {
    const { refreshToken, accessToken } = await this.authService.getLoginTokens(req.user);
    return await this.authService.userService.onBeforeLoginResponse(
      req.user,
      refreshToken,
      accessToken,
    );
  }

  @UseGuards(AccessTokenAuthGuard)
  @Get('logout')
  logout(@Req() req: Request) {
    return { message: 'Logout successfully' };
  }

  @UseGuards(RefreshTokenAuthGuard)
  @Get('refresh')
  async refreshTokens(@Req() req: Request) {
    const { user, accessToken, refreshToken } = await this.authService.refreshToken(req.user);
    return await this.authService.userService.onBeforeRefreshTokenResponse(
      req.user,
      user,
      refreshToken,
      accessToken,
    );
  }

  @UseGuards(AccessTokenAuthGuard)
  @Get('/me')
  me(@Req() req: Request) {
    return req.user;
  }
}

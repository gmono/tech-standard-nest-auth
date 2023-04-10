import { Body, Controller, HttpCode, Post, Req, UnprocessableEntityException, UseGuards } from '@nestjs/common';
import { AuthService, LocalAuthGuard } from '@sun-asterisk/nest-auth';
import { UserRegisterDto } from './types';

@Controller('')
export class UserController {
  constructor(private authService: AuthService) { }

  @Post('/register')
  async register(@Body() registerData: UserRegisterDto) {
    if (!registerData.username || !registerData.email || !registerData.password) {
      throw new UnprocessableEntityException('Invalid user info');
    }

    const { user, token } = await this.authService.userService.register(registerData);
    // Send token to the user email
    console.log({ token });

    return user;
  }

  @HttpCode(200)
  @UseGuards(LocalAuthGuard)
  @Post('/login')
  async login(@Req() req) {
    return await this.authService.getLoginTokens(req.user);
  }

  @HttpCode(200)
  @Post('/forgot-password')
  async forgotPassword(@Body() body) {
    const { user, token } = await this.authService.userService.generateForgotPasswordToken(
      body?.identity,
    );
    // Send token to the user email
    console.log({ token });
    
    return {
      status: 'ok',
    };
  }
}
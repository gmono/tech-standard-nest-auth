import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { ObjectLiteral } from 'typeorm';

@Injectable()
export class LocalStrategy<Entity extends ObjectLiteral> extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService<Entity>) {
    super({
        usernameField: authService.userService.requestUsernameField || 'username',
        passwordField: authService.userService.requestPasswordField || 'password',
      },
    );
  }

  async validate(username: string, password: string): Promise<Entity> {
    const user = await this.authService.userService.login(username, password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}

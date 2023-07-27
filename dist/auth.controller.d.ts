/// <reference types="passport" />
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
export declare class AuthController {
    private authService;
    constructor(authService: AuthService);
    register(body: any): Promise<any>;
    confirm(req: Request): Promise<any>;
    login(req: Request): Promise<any>;
    forgotPassword(body: any): Promise<any>;
    verifyForgotPaswordToken(req: Request): Promise<any>;
    changePassword(body: any, req: Request): Promise<any>;
    logout(req: Request): Promise<any>;
    refreshTokens(body: any, req: Request): Promise<any>;
    passportAuthenticate(req: Request, res: Response): Promise<void>;
    passportAuthenticateCallback(req: Request): Promise<any>;
    me(req: Request): Express.User;
}

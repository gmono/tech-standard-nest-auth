import { HttpServer } from '@nestjs/common';
export declare const createTestUserData: (suffix: string) => {
    email: string;
    password: string;
    username: string;
};
export declare const getLoginResponse: (httpServer: HttpServer, data: any) => Promise<{
    access_token: string;
    refresh_token: string;
}>;

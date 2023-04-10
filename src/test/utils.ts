import { HttpServer } from '@nestjs/common';
import * as request from 'supertest';

export const createTestUserData = (suffix: string) => {
  return {
    email: `testuser${suffix}@local.ltd`,
    password: `testuser${suffix}`,
    username: `testuser${suffix}`,
  };
}
export const getLoginResponse = async (httpServer: HttpServer, data: any): Promise<{
  access_token: string;
  refresh_token: string;
}> => {
  const loginResponse = await request(httpServer)
    .post('/login')
    .send(data)
    .expect(200);
  return loginResponse.body;
};

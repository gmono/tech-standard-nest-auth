import * as express from 'express';
import { passportVerifier, passportVerifierWithRequest } from '../helpers';

describe('helpers', () => {
  it('passportVerifier should run', async () => {
    const done = jest.fn();
    const profile = {
      provider: 'facebook',
      id: '111',
      displayName: 'TestUser',
    };

    passportVerifier(
      'access_token',
      'refresh_token',
      profile,
      done,
    );

    expect(done).toBeCalledWith(null, {
      accessToken: 'access_token',
      refreshToken: 'refresh_token',
      profile,
    });
  });

  it('passportVerifierWithRequest should run', async () => {
    const done = jest.fn();
    const req = null as unknown as express.Request;
    const profile = {
      provider: 'facebook',
      id: '111',
      displayName: 'TestUser',
    };

    passportVerifierWithRequest(
      req,
      'access_token',
      'refresh_token',
      profile,
      done,
    );

    expect(done).toBeCalledWith(null, {
      req,
      accessToken: 'access_token',
      refreshToken: 'refresh_token',
      profile,
    });
  });
});
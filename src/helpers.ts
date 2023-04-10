import * as crypto from 'crypto';
import {
  AuthModuleOptions,
  PassportVerifyFunction,
  PassportVerifyFunctionWithRequest,
} from './types';

const ALGORITHM = 'aes-256-gcm';

// Twitter verifier signature: (token, tokenSecret, profile, done) => void
export const passportVerifier: PassportVerifyFunction = (
  accessToken,
  refreshToken,
  profile,
  done,
) => done(null, { accessToken, refreshToken, profile });

export const passportVerifierWithRequest: PassportVerifyFunctionWithRequest = (
  req,
  accessToken,
  refreshToken,
  profile,
  done,
) => done(null, { req, accessToken, refreshToken, profile });

export const getStrategyError = (
  err: any,
  user: any,
  info: any,
  status: any,
): Error => {
  if (err) {
    if (err instanceof Error) {
      return err;
    }

    if (typeof err === 'string') {
      return new Error(err);
    }

    return new Error(JSON.stringify(err));
  }

  if (!user) {
    const infoObj = typeof info === 'object' && info !== null ? info : { info };
    const message = infoObj.message || undefined;

    return new Error(message || JSON.stringify({ status, ...infoObj }));
  }

  return null;
};

export const encrypt = (input: string, key: string): string => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const enc = Buffer.concat([cipher.update(input, 'utf8'), cipher.final()]);
  const ciphertext = [enc, iv, cipher.getAuthTag()]
    .map((e) => e.toString('base64'))
    .join('~');

  return Buffer.from(ciphertext).toString('base64');
};

export const decrypt = (encryptedText: string, key: string): string => {
  const ciphertext = Buffer.from(encryptedText, 'base64').toString('utf8');
  const [enc, iv, authTag] = ciphertext
    .split('~')
    .map((e) => Buffer.from(e, 'base64'));
  const decipher = crypto
    .createDecipheriv(ALGORITHM, key, iv)
    .setAuthTag(authTag);

  return Buffer.concat([decipher.update(enc), decipher.final()]).toString();
};

// Get the expiration time of a JWT token in unix time seconds
export const getTokenExpiresIn = (token: string): number => {
  try {
    const tokenObj = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64').toString('utf8'),
    );

    return tokenObj.exp;
  } catch (e) {
    return 0;
  }
};

export const getOptions = <Entity, JwtPayload>(
  opts: AuthModuleOptions<Entity, JwtPayload>,
): AuthModuleOptions<Entity, JwtPayload> => {
  const newOpts: AuthModuleOptions<Entity, JwtPayload> = {
    authKey: opts.authKey,
    typeormUserEntity: opts.typeormUserEntity || undefined,
    userService: opts.userService || undefined,
    imports: opts.imports || [],
    disableRouter: opts?.disableRouter || false,
    config: Object.assign(
      {
        enableRefreshTokenRotation:
          opts?.config?.enableRefreshTokenRotation || false,
        passwordHashSecret: opts?.config?.passwordHashSecret || opts.authKey,
        jwt: Object.assign(
          {
            secret: opts.authKey,
            signOptions: Object.assign(
              {
                expiresIn: '900s',
              },
              opts?.config?.jwt?.signOptions || {},
            ),
            refresh: Object.assign(
              {
                secret: opts.authKey,
                expiresIn: '7d',
              },
              opts?.config?.jwt?.refresh || {},
            ),
          },
          opts?.config?.jwt || {},
        ),
        recovery: Object.assign(
          {
            tokenExpiresIn: 7200,
            tokenSecret: opts.authKey,
          },
          opts?.config?.recovery || {},
        ),
        passportStrategies: opts?.config?.passportStrategies || [],
      },
      // opts?.config || {},
    ),
  };

  return newOpts;
};

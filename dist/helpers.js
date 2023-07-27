"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getOptions = exports.getTokenExpiresIn = exports.decrypt = exports.encrypt = exports.getStrategyError = exports.passportVerifierWithRequest = exports.passportVerifier = void 0;
const crypto = require("crypto");
const ALGORITHM = 'aes-256-gcm';
const passportVerifier = (accessToken, refreshToken, profile, done) => done(null, { accessToken, refreshToken, profile });
exports.passportVerifier = passportVerifier;
const passportVerifierWithRequest = (req, accessToken, refreshToken, profile, done) => done(null, { req, accessToken, refreshToken, profile });
exports.passportVerifierWithRequest = passportVerifierWithRequest;
const getStrategyError = (err, user, info, status) => {
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
        return new Error(message || JSON.stringify(Object.assign({ status }, infoObj)));
    }
    return null;
};
exports.getStrategyError = getStrategyError;
const encrypt = (input, key) => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const enc = Buffer.concat([cipher.update(input, 'utf8'), cipher.final()]);
    const ciphertext = [enc, iv, cipher.getAuthTag()]
        .map((e) => e.toString('base64'))
        .join('~');
    return Buffer.from(ciphertext).toString('base64');
};
exports.encrypt = encrypt;
const decrypt = (encryptedText, key) => {
    const ciphertext = Buffer.from(encryptedText, 'base64').toString('utf8');
    const [enc, iv, authTag] = ciphertext
        .split('~')
        .map((e) => Buffer.from(e, 'base64'));
    const decipher = crypto
        .createDecipheriv(ALGORITHM, key, iv)
        .setAuthTag(authTag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString();
};
exports.decrypt = decrypt;
const getTokenExpiresIn = (token) => {
    try {
        const tokenObj = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
        return tokenObj.exp;
    }
    catch (e) {
        return 0;
    }
};
exports.getTokenExpiresIn = getTokenExpiresIn;
const getOptions = (opts) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j;
    const newOpts = {
        authKey: opts.authKey,
        typeormUserEntity: opts.typeormUserEntity || undefined,
        userService: opts.userService || undefined,
        imports: opts.imports || [],
        disableRouter: (opts === null || opts === void 0 ? void 0 : opts.disableRouter) || false,
        config: Object.assign({
            enableRefreshTokenRotation: ((_a = opts === null || opts === void 0 ? void 0 : opts.config) === null || _a === void 0 ? void 0 : _a.enableRefreshTokenRotation) || false,
            passwordHashSecret: ((_b = opts === null || opts === void 0 ? void 0 : opts.config) === null || _b === void 0 ? void 0 : _b.passwordHashSecret) || opts.authKey,
            jwt: Object.assign({
                secret: opts.authKey,
                signOptions: Object.assign({
                    expiresIn: '900s',
                }, ((_d = (_c = opts === null || opts === void 0 ? void 0 : opts.config) === null || _c === void 0 ? void 0 : _c.jwt) === null || _d === void 0 ? void 0 : _d.signOptions) || {}),
                refresh: Object.assign({
                    secret: opts.authKey,
                    expiresIn: '7d',
                }, ((_f = (_e = opts === null || opts === void 0 ? void 0 : opts.config) === null || _e === void 0 ? void 0 : _e.jwt) === null || _f === void 0 ? void 0 : _f.refresh) || {}),
            }, ((_g = opts === null || opts === void 0 ? void 0 : opts.config) === null || _g === void 0 ? void 0 : _g.jwt) || {}),
            recovery: Object.assign({
                tokenExpiresIn: 7200,
                tokenSecret: opts.authKey,
            }, ((_h = opts === null || opts === void 0 ? void 0 : opts.config) === null || _h === void 0 ? void 0 : _h.recovery) || {}),
            passportStrategies: ((_j = opts === null || opts === void 0 ? void 0 : opts.config) === null || _j === void 0 ? void 0 : _j.passportStrategies) || [],
        }),
    };
    return newOpts;
};
exports.getOptions = getOptions;

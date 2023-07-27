"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseUserService = void 0;
const argon2 = require("argon2");
const common_1 = require("@nestjs/common");
const helpers_1 = require("./helpers");
const typeorm_1 = require("typeorm");
const types_1 = require("./types");
let BaseUserService = class BaseUserService {
    constructor(userRepository, options) {
        this.userRepository = userRepository;
        this.options = options;
        this.IDField = 'id';
        this.dbIdentityFields = ['username', 'email'];
        this.dbPasswordField = 'password';
        this.requestUsernameField = 'username';
        this.requestPasswordField = 'password';
    }
    register(data) {
        return __awaiter(this, void 0, void 0, function* () {
            const userData = data;
            this.dbIdentityFields.forEach(identityField => {
                if (!userData[identityField]) {
                    throw new common_1.UnprocessableEntityException('Invalid user register data');
                }
            });
            const existedUser = yield this.userRepository.findOne({
                where: this.dbIdentityFields.map((field) => ({
                    [field]: userData[field],
                })),
            });
            if (existedUser) {
                throw new common_1.UnprocessableEntityException('User existed');
            }
            const passwordField = this.dbPasswordField;
            userData[passwordField] = (yield this.hashPassword(userData[passwordField]));
            const user = this.userRepository.create(userData);
            const savedUser = yield this.userRepository.save(user);
            delete savedUser[passwordField];
            const token = (0, helpers_1.encrypt)(JSON.stringify({
                [this.IDField]: savedUser[this.IDField],
                createdAt: new Date().getTime(),
            }), this.options.recovery.tokenSecret);
            return { user: savedUser, token };
        });
    }
    login(username, password) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!username || !password) {
                throw new common_1.UnauthorizedException('Invalid login credentials');
            }
            const user = yield this.userRepository.findOne({
                where: this.dbIdentityFields.map((field) => ({
                    [field]: username,
                })),
            });
            if (!user) {
                throw new common_1.UnauthorizedException();
            }
            const validPassword = yield this.verifyPassword(password, user[this.dbPasswordField]);
            if (!user || !validPassword) {
                throw new common_1.UnauthorizedException();
            }
            return user;
        });
    }
    generateForgotPasswordToken(identityValue) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!identityValue) {
                throw new common_1.UnauthorizedException('Invalid identity value');
            }
            const user = yield this.userRepository.findOne({
                where: this.dbIdentityFields.map((field) => ({
                    [field]: identityValue,
                })),
            });
            if (!user) {
                throw new common_1.UnauthorizedException();
            }
            const token = (0, helpers_1.encrypt)(JSON.stringify({
                [this.IDField]: user[this.IDField],
                createdAt: new Date().getTime(),
            }), this.options.recovery.tokenSecret);
            return { user, token };
        });
    }
    verifyToken(token, ignoreExpired) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!token) {
                throw new common_1.UnauthorizedException('Invalid token');
            }
            let result = {
                createdAt: 0,
            };
            try {
                const decrypted = (0, helpers_1.decrypt)(token, this.options.recovery.tokenSecret);
                result = JSON.parse(decrypted);
            }
            catch (e) {
                throw new common_1.UnauthorizedException();
            }
            const now = new Date().getTime();
            const expiresInSeconds = this.options.recovery.tokenExpiresIn * 1000;
            const user = yield this.userRepository.findOneBy({
                [this.IDField]: result[this.IDField],
            });
            if (user && (ignoreExpired ||
                now - result.createdAt <= expiresInSeconds)) {
                return { user, createdAt: result.createdAt };
            }
        });
    }
    changePassword(user, newPassword, isForgot, oldPassword) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!user) {
                throw new common_1.UnauthorizedException('User not found');
            }
            if (!newPassword) {
                throw new common_1.UnauthorizedException('New password is required');
            }
            if (!isForgot && !oldPassword) {
                throw new common_1.UnauthorizedException('Old password is required');
            }
            if (!isForgot && oldPassword) {
                const isOldPasswordValid = yield this.verifyPassword(oldPassword, user[this.dbPasswordField]);
                if (!isOldPasswordValid) {
                    throw new common_1.UnauthorizedException('Old password is incorrect');
                }
            }
            const passwordField = this.dbPasswordField;
            user[passwordField] = (yield this.hashPassword(newPassword));
            yield this.userRepository.save(user);
            return false;
        });
    }
    hashPassword(input) {
        return __awaiter(this, void 0, void 0, function* () {
            return argon2.hash(input, {
                secret: Buffer.from(this.options.passwordHashSecret),
            });
        });
    }
    verifyPassword(input, hashedPassword) {
        return __awaiter(this, void 0, void 0, function* () {
            return argon2.verify(hashedPassword, input, {
                secret: Buffer.from(this.options.passwordHashSecret),
            });
        });
    }
    createJwtAccessTokenPayload(user) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!user[this.IDField]) {
                throw new Error(`${this.IDField} is not defined in user object: ${JSON.stringify(user)}`);
            }
            const payload = {
                sub: {
                    [this.IDField]: user[this.IDField],
                },
            };
            return payload;
        });
    }
    createJwtRefreshTokenPayload(user) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.createJwtAccessTokenPayload(user);
        });
    }
    jwtValidator(payload) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!payload.sub[this.IDField]) {
                throw new Error('Invalid JWT payload');
            }
            const user = yield this.userRepository.findOneBy({
                [this.IDField]: payload.sub[this.IDField],
            });
            if (!user) {
                throw new common_1.UnauthorizedException();
            }
            return user;
        });
    }
    onBeforePassportAuthenticateResponse(provider, data) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('Method not implemented.');
        });
    }
    onBeforeRegisterResponse(body, token, user) {
        return __awaiter(this, void 0, void 0, function* () {
            return {
                user,
            };
        });
    }
    onBeforeLoginResponse(user, refreshToken, accessToken, refreshTokenExpiresAt, accessTokenExpiresAt) {
        return __awaiter(this, void 0, void 0, function* () {
            return {
                refresh_token: refreshToken,
                access_token: accessToken,
                token_type: 'Bearer',
                expires_at: accessTokenExpiresAt,
            };
        });
    }
    onBeforeForgotPasswordResponse(user, token) {
        return __awaiter(this, void 0, void 0, function* () {
            return {
                ok: true,
                type: 'forgotPassword',
            };
        });
    }
    onBeforeVerifyForgotPasswordResponse(user, token, createdAt) {
        return __awaiter(this, void 0, void 0, function* () {
            return {
                ok: true,
                type: 'verifyForgotPassword',
            };
        });
    }
    onBeforeVerifyRegisterResponse(user, token, createdAt) {
        return __awaiter(this, void 0, void 0, function* () {
            return {
                ok: true,
                type: 'verifyRegister',
            };
        });
    }
    onBeforeChangePasswordResponse(user, oldPassword, newPassword, success) {
        return __awaiter(this, void 0, void 0, function* () {
            return {
                ok: true,
                type: 'changePassword',
            };
        });
    }
    onBeforeLogoutResponse(accessToken) {
        return __awaiter(this, void 0, void 0, function* () {
            return null;
        });
    }
    onBeforeRefreshTokenResponse(user, refreshToken, accessToken, refreshTokenExpiresAt, accessTokenExpiresAt) {
        return __awaiter(this, void 0, void 0, function* () {
            return {
                token_type: 'Bearer',
                refresh_token: refreshToken,
                access_token: accessToken,
                expires_at: accessTokenExpiresAt,
            };
        });
    }
};
BaseUserService = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, common_1.Inject)(types_1.AUTH_CONFIG)),
    __metadata("design:paramtypes", [typeorm_1.Repository, Object])
], BaseUserService);
exports.BaseUserService = BaseUserService;

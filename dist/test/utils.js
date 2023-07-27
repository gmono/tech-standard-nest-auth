"use strict";
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
exports.getLoginResponse = exports.createTestUserData = void 0;
const request = require("supertest");
const createTestUserData = (suffix) => {
    return {
        email: `testuser${suffix}@local.ltd`,
        password: `testuser${suffix}`,
        username: `testuser${suffix}`,
    };
};
exports.createTestUserData = createTestUserData;
const getLoginResponse = (httpServer, data) => __awaiter(void 0, void 0, void 0, function* () {
    const loginResponse = yield request(httpServer)
        .post('/login')
        .send(data)
        .expect(200);
    return loginResponse.body;
});
exports.getLoginResponse = getLoginResponse;

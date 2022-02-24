"use strict";
// Copyright IBM Corp. 2020. All Rights Reserved.
// Node module: @loopback/authentication-jwt
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const testlab_1 = require("@loopback/testlab");
const bcryptjs_1 = require("bcryptjs");
const _ = (0, tslib_1.__importStar)(require("lodash"));
const __1 = require("../..");
const __2 = require("../../");
const application_1 = require("../fixtures/application");
describe('jwt authentication', () => {
    let app;
    let client;
    let token;
    let userRepo;
    let refreshToken;
    let tokenAuth;
    before(givenRunningApplication);
    before(() => {
        client = (0, testlab_1.createRestAppClient)(app);
    });
    after(async () => {
        await app.stop();
    });
    it(`user login successfully`, async () => {
        const credentials = { email: 'jane@doe.com', password: 'opensesame' };
        const res = await client.post('/users/login').send(credentials).expect(200);
        token = res.body.token;
    });
    it('whoAmI returns the login user id', async () => {
        const res = await client
            .get('/whoAmI')
            .set('Authorization', 'Bearer ' + token)
            .expect(200);
        (0, testlab_1.expect)(res.text).to.equal('f48b7167-8d95-451c-bbfc-8a12cd49e763');
    });
    it('generates openapi spec provided by enhancer', async () => {
        var _a;
        const spec = await app.restServer.getApiSpec();
        (0, testlab_1.expect)(spec.security).to.eql(__2.OPERATION_SECURITY_SPEC);
        (0, testlab_1.expect)((_a = spec.components) === null || _a === void 0 ? void 0 : _a.securitySchemes).to.eql(__2.SECURITY_SCHEME_SPEC);
    });
    it(`user login and token granted successfully`, async () => {
        const credentials = { email: 'jane@doe.com', password: 'opensesame' };
        const res = await client
            .post('/users/refresh-login')
            .send(credentials)
            .expect(200);
        refreshToken = res.body.refreshToken;
    });
    it(`user sends refresh token and new access token issued`, async () => {
        const tokenArg = { refreshToken: refreshToken };
        const res = await client.post('/refresh/').send(tokenArg).expect(200);
        tokenAuth = res.body.accessToken;
    });
    it('whoAmI returns the login user id using token generated from refresh', async () => {
        const res = await client
            .get('/whoAmI')
            .set('Authorization', 'Bearer ' + tokenAuth)
            .expect(200);
        (0, testlab_1.expect)(res.text).to.equal('f48b7167-8d95-451c-bbfc-8a12cd49e763');
    });
    /*
     ============================================================================
     TEST HELPERS
     ============================================================================
     */
    async function givenRunningApplication() {
        app = new application_1.TestApplication({
            rest: (0, testlab_1.givenHttpServerConfig)(),
        });
        await app.boot();
        userRepo = await app.get(__1.UserServiceBindings.USER_REPOSITORY);
        await createUsers();
        await app.start();
    }
    async function createUsers() {
        const hashedPassword = await hashPassword('opensesame', 10);
        //providing UUID() to test
        const users = [
            {
                id: 'a75337c0-78d2-4b44-8037-20e22d5e2508',
                username: 'John',
                email: 'john@doe.com',
                password: hashedPassword,
            },
            {
                id: 'f48b7167-8d95-451c-bbfc-8a12cd49e763',
                username: 'Jane',
                email: 'jane@doe.com',
                password: hashedPassword,
            },
            {
                id: 'bbb5e8a0-fc86-4573-aeab-c950c38dc7a1',
                username: 'Bob',
                email: 'bob@projects.com',
                password: hashedPassword,
            },
        ];
        for (const u of users) {
            await userRepo.create(_.pick(u, ['id', 'email', 'username']));
            await userRepo
                .userCredentials(u.id)
                .create({ password: u.password, userId: u.id });
        }
    }
    async function hashPassword(password, rounds) {
        const salt = await (0, bcryptjs_1.genSalt)(rounds);
        return (0, bcryptjs_1.hash)(password, salt);
    }
});
//# sourceMappingURL=jwt.component.test.js.map
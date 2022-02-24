"use strict";
// Copyright IBM Corp. 2020. All Rights Reserved.
// Node module: @loopback/authentication-jwt
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserController = exports.CredentialsRequestBody = exports.NewUserRequest = void 0;
const tslib_1 = require("tslib");
const authentication_1 = require("@loopback/authentication");
const core_1 = require("@loopback/core");
const repository_1 = require("@loopback/repository");
const rest_1 = require("@loopback/rest");
const security_1 = require("@loopback/security");
const bcryptjs_1 = require("bcryptjs");
const __1 = require("../../../");
const repositories_1 = require("../../../repositories");
// Describes the schema of grant object
const RefreshGrantSchema = {
    type: 'object',
    required: ['refreshToken'],
    properties: {
        refreshToken: {
            type: 'string',
        },
    },
};
// Describes the request body of grant object
const RefreshGrantRequestBody = {
    description: 'Reissuing Acess Token',
    required: true,
    content: {
        'application/json': { schema: RefreshGrantSchema },
    },
};
// Describe the schema of user credentials
const CredentialsSchema = {
    type: 'object',
    required: ['email', 'password'],
    properties: {
        email: {
            type: 'string',
            format: 'email',
        },
        password: {
            type: 'string',
            minLength: 8,
        },
    },
};
let NewUserRequest = class NewUserRequest extends __1.User {
};
(0, tslib_1.__decorate)([
    (0, repository_1.property)({
        type: 'string',
        required: true,
    }),
    (0, tslib_1.__metadata)("design:type", String)
], NewUserRequest.prototype, "password", void 0);
NewUserRequest = (0, tslib_1.__decorate)([
    (0, repository_1.model)()
], NewUserRequest);
exports.NewUserRequest = NewUserRequest;
exports.CredentialsRequestBody = {
    description: 'The input of login function',
    required: true,
    content: {
        'application/json': { schema: CredentialsSchema },
    },
};
let UserController = class UserController {
    constructor(jwtService, userService, user, userRepository, refreshService) {
        this.jwtService = jwtService;
        this.userService = userService;
        this.user = user;
        this.userRepository = userRepository;
        this.refreshService = refreshService;
    }
    async signUp(newUserRequest) {
        const password = await (0, bcryptjs_1.hash)(newUserRequest.password, await (0, bcryptjs_1.genSalt)());
        delete newUserRequest.password;
        const savedUser = await this.userRepository.create(newUserRequest);
        await this.userRepository.userCredentials(savedUser.id).create({ password });
        return savedUser;
    }
    /**
     * A login function that returns an access token. After login, include the token
     * in the next requests to verify your identity.
     * @param credentials User email and password
     */
    async login(credentials) {
        // ensure the user exists, and the password is correct
        const user = await this.userService.verifyCredentials(credentials);
        // convert a User object into a UserProfile object (reduced set of properties)
        const userProfile = this.userService.convertToUserProfile(user);
        // create a JSON Web Token based on the user profile
        const token = await this.jwtService.generateToken(userProfile);
        return { token };
    }
    async whoAmI() {
        return this.user[security_1.securityId];
    }
    /**
     * A login function that returns refresh token and access token.
     * @param credentials User email and password
     */
    async refreshLogin(credentials) {
        // ensure the user exists, and the password is correct
        const user = await this.userService.verifyCredentials(credentials);
        // convert a User object into a UserProfile object (reduced set of properties)
        const userProfile = this.userService.convertToUserProfile(user);
        const accessToken = await this.jwtService.generateToken(userProfile);
        const tokens = await this.refreshService.generateToken(userProfile, accessToken);
        return tokens;
    }
    async refresh(refreshGrant) {
        return this.refreshService.refreshToken(refreshGrant.refreshToken);
    }
};
(0, tslib_1.__decorate)([
    (0, rest_1.post)('/users/signup', {
        responses: {
            '200': {
                description: 'User model instance',
                content: {
                    'application/json': {
                        schema: {
                            'x-ts-type': __1.User,
                        },
                    },
                },
            },
        },
    }),
    (0, tslib_1.__param)(0, (0, rest_1.requestBody)({
        content: {
            'application/json': {
                schema: CredentialsSchema,
            },
        },
    })),
    (0, tslib_1.__metadata)("design:type", Function),
    (0, tslib_1.__metadata)("design:paramtypes", [NewUserRequest]),
    (0, tslib_1.__metadata)("design:returntype", Promise)
], UserController.prototype, "signUp", null);
(0, tslib_1.__decorate)([
    (0, rest_1.post)('/users/login', {
        responses: {
            '200': {
                description: 'Token',
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                token: {
                                    type: 'string',
                                },
                            },
                        },
                    },
                },
            },
        },
    }),
    (0, tslib_1.__param)(0, (0, rest_1.requestBody)(exports.CredentialsRequestBody)),
    (0, tslib_1.__metadata)("design:type", Function),
    (0, tslib_1.__metadata)("design:paramtypes", [Object]),
    (0, tslib_1.__metadata)("design:returntype", Promise)
], UserController.prototype, "login", null);
(0, tslib_1.__decorate)([
    (0, authentication_1.authenticate)('jwt'),
    (0, rest_1.get)('/whoAmI', {
        responses: {
            '200': {
                description: '',
                schema: {
                    type: 'string',
                },
            },
        },
    }),
    (0, tslib_1.__metadata)("design:type", Function),
    (0, tslib_1.__metadata)("design:paramtypes", []),
    (0, tslib_1.__metadata)("design:returntype", Promise)
], UserController.prototype, "whoAmI", null);
(0, tslib_1.__decorate)([
    (0, rest_1.post)('/users/refresh-login', {
        responses: {
            '200': {
                description: 'Token',
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                accessToken: {
                                    type: 'string',
                                },
                                refreshToken: {
                                    type: 'string',
                                },
                            },
                        },
                    },
                },
            },
        },
    }),
    (0, tslib_1.__param)(0, (0, rest_1.requestBody)(exports.CredentialsRequestBody)),
    (0, tslib_1.__metadata)("design:type", Function),
    (0, tslib_1.__metadata)("design:paramtypes", [Object]),
    (0, tslib_1.__metadata)("design:returntype", Promise)
], UserController.prototype, "refreshLogin", null);
(0, tslib_1.__decorate)([
    (0, rest_1.post)('/refresh', {
        responses: {
            '200': {
                description: 'Token',
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties: {
                                accessToken: {
                                    type: 'object',
                                },
                            },
                        },
                    },
                },
            },
        },
    }),
    (0, tslib_1.__param)(0, (0, rest_1.requestBody)(RefreshGrantRequestBody)),
    (0, tslib_1.__metadata)("design:type", Function),
    (0, tslib_1.__metadata)("design:paramtypes", [Object]),
    (0, tslib_1.__metadata)("design:returntype", Promise)
], UserController.prototype, "refresh", null);
UserController = (0, tslib_1.__decorate)([
    (0, tslib_1.__param)(0, (0, core_1.inject)(__1.TokenServiceBindings.TOKEN_SERVICE)),
    (0, tslib_1.__param)(1, (0, core_1.inject)(__1.UserServiceBindings.USER_SERVICE)),
    (0, tslib_1.__param)(2, (0, core_1.inject)(security_1.SecurityBindings.USER, { optional: true })),
    (0, tslib_1.__param)(3, (0, core_1.inject)(__1.UserServiceBindings.USER_REPOSITORY)),
    (0, tslib_1.__param)(4, (0, core_1.inject)(__1.RefreshTokenServiceBindings.REFRESH_TOKEN_SERVICE)),
    (0, tslib_1.__metadata)("design:paramtypes", [Object, Object, Object, repositories_1.UserRepository, Object])
], UserController);
exports.UserController = UserController;
//# sourceMappingURL=user.controller.js.map
import { TokenService, UserService } from '@loopback/authentication';
import { SchemaObject } from '@loopback/rest';
import { UserProfile } from '@loopback/security';
import { TokenObject, User } from '../../../';
import { UserRepository } from '../../../repositories';
import { Credentials } from '../../../services/user.service';
import { RefreshTokenService } from '../../../types';
declare type RefreshGrant = {
    refreshToken: string;
};
export declare class NewUserRequest extends User {
    password: string;
}
export declare const CredentialsRequestBody: {
    description: string;
    required: boolean;
    content: {
        'application/json': {
            schema: SchemaObject;
        };
    };
};
export declare class UserController {
    jwtService: TokenService;
    userService: UserService<User, Credentials>;
    private user;
    userRepository: UserRepository;
    refreshService: RefreshTokenService;
    constructor(jwtService: TokenService, userService: UserService<User, Credentials>, user: UserProfile, userRepository: UserRepository, refreshService: RefreshTokenService);
    signUp(newUserRequest: NewUserRequest): Promise<User>;
    /**
     * A login function that returns an access token. After login, include the token
     * in the next requests to verify your identity.
     * @param credentials User email and password
     */
    login(credentials: Credentials): Promise<{
        token: string;
    }>;
    whoAmI(): Promise<string>;
    /**
     * A login function that returns refresh token and access token.
     * @param credentials User email and password
     */
    refreshLogin(credentials: Credentials): Promise<TokenObject>;
    refresh(refreshGrant: RefreshGrant): Promise<TokenObject>;
}
export {};

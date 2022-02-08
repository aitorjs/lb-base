import {
  AuthenticationComponent,
  registerAuthenticationStrategy
} from '@loopback/authentication';
import {AuthorizationComponent} from '@loopback/authorization';
import {BootMixin} from '@loopback/boot';
import {ApplicationConfig, createBindingFromClass} from '@loopback/core';
import {RepositoryMixin} from '@loopback/repository';
import {OpenApiSpec, RestApplication} from '@loopback/rest';
import {
  RestExplorerBindings,
  RestExplorerComponent
} from '@loopback/rest-explorer';
import {ServiceMixin} from '@loopback/service-proxy';
import {MigrationBindings, MigrationComponent} from 'loopback4-migration';
import path from 'path';
import {JWTAuthenticationStrategy} from './authentication-strategies/jwt-strategy';
import {MongoDataSource} from './datasources';
import {
  PasswordHasherBindings,
  TokenServiceBindings,
  TokenServiceConstants,
  UserServiceBindings
} from './keys';
import {BcryptHasher, JWTService, MyUserService} from './services';
import {SECURITY_SCHEME_SPEC} from './utils/security-spec';
require('dotenv').config();
export {ApplicationConfig};

export class LbBaseApplication extends BootMixin(
  ServiceMixin(RepositoryMixin(RestApplication)),
) {
  constructor(options: ApplicationConfig = {}) {
    super(options);

    this.setUpBindings();

    // Set up the custom sequence
    // this.sequence(MySequence);

    // Set up default home page
    this.static('/', path.join(__dirname, '../public'));

    // Customize @loopback/rest-explorer configuration here
    this.configure(RestExplorerBindings.COMPONENT).to({
      path: '/explorer',
    });
    this.component(RestExplorerComponent);

    this.component(AuthenticationComponent);
    this.component(AuthorizationComponent);

    this.add(createBindingFromClass(JWTAuthenticationStrategy));
    registerAuthenticationStrategy(this, JWTAuthenticationStrategy);

    const spec: OpenApiSpec = {
      openapi: '3.0.0',
      info: {title: 'pkg.name', version: 'pkg.version'},
      paths: {},
      components: {securitySchemes: SECURITY_SCHEME_SPEC},
      servers: [{url: '/api'}],
      // security: SECURITY_SPEC,
    };
    this.api(spec);

    // Configure migration component
    this.bind(MigrationBindings.CONFIG).to({
      dataSourceName: MongoDataSource.dataSourceName,
    });
    // Bind migration component related elements
    this.component(MigrationComponent);

    this.projectRoot = __dirname;
    // Customize @loopback/boot Booter Conventions here
    this.bootOptions = {
      controllers: {
        // Customize ControllerBooter Conventions here
        dirs: ['controllers'],
        extensions: ['.controller.js'],
        nested: true,
      },
    };
  }

  /*   async migrateSchema(options?: SchemaMigrationOptions) {
      await super.migrateSchema(options);

      console.log("lb4 migration")
      const userRepo = await this.getRepository(UserRepository);
      const found = await userRepo.findOne({where: {email: 'user2333@example.com'}});
      if (found) {
        userRepo.updateById(found.id, {firstName: "done"});
      } else {
        await userRepo.create({email: 'we1lcome@w11.com', role: "user"});
      }
    } */

  private setUpBindings(): void {
    // Bind package.json to the application context
    // this.bind(PackageKey).to(pkg);

    this.bind(TokenServiceBindings.TOKEN_SECRET).to(
      TokenServiceConstants.TOKEN_SECRET_VALUE!,
    );

    this.bind(TokenServiceBindings.TOKEN_EXPIRES_IN).to(
      TokenServiceConstants.TOKEN_EXPIRES_IN_VALUE,
    );

    this.bind(TokenServiceBindings.TOKEN_SERVICE).toClass(JWTService);

    // // Bind bcrypt hash services
    this.bind(PasswordHasherBindings.ROUNDS).to(10);
    this.bind(PasswordHasherBindings.PASSWORD_HASHER).toClass(BcryptHasher);

    this.bind(UserServiceBindings.USER_SERVICE).toClass(MyUserService);

    // this.bind('repositories.UserRepository').toClass(UserRepository);
    // this.bind('datasources.mongo').toClass(MongoDataSource);
  }
}

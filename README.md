# lb-base
## Use

- Install docker and docker-compose on your machine.
- Create .env file.
- Open the envirotment you need: prod, dev, testing.
- Go to http://localhost:3000 on prod and dev.

## Environments
### Prod(uction).
- docker network create back
- npm run start:prod:docker

### Dev(elopment).
- docker network create back
- npm run start:dev:docker

### Testing. Functional tests.
- docker network create back
- npm run start:test:docker



This application is generated using [LoopBack 4 CLI](https://loopback.io/doc/en/lb4/Command-line-interface.html) with the
[initial project layout](https://loopback.io/doc/en/lb4/Loopback-application-layout.html).

## Install dependencies

By default, dependencies were installed when this application was generated.
# Use

- Install docker and docker-compose on your machine.
- Create .env file.
- ```npm run start:docker```
- Go to http://localhost:3000

# Functional tests

- docker exec -it [API_CONTAINERID/ API_CONTAINERNAME] npm run test
(docker exec -it lb-base_api npm run test)

Whenever dependencies in `package.json` are changed, run the following command:

```sh
npm install
```

To only install resolved dependencies in `package-lock.json`:

```sh
npm ci
```

## Run the application
Create .env file with this content:
```bash
ADMIN_EMAIL = "<ADMIN_EMAIL>"
ADMIN_PASS = "<ADMIN_PASS>"
```
Start application:
```sh
npm start
```

You can also run `node .` to skip the build step.

Open http://127.0.0.1:3000 in your browser.

## Rebuild the project

To incrementally build the project:

```sh
npm run build
```

To force a full build by cleaning up cached artifacts:

```sh
npm run rebuild
```

## Fix code style and formatting issues

```sh
npm run lint
```

To automatically fix such issues:

```sh
npm run lint:fix
```

## Other useful commands

- `npm run migrate`: Migrate database schemas for models
- `npm run openapi-spec`: Generate OpenAPI spec into a file
- `npm run docker:build`: Build a Docker image for this application
- `npm run docker:run`: Run this application inside a Docker container

## Tests

```sh
npm test
```

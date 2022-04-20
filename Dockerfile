FROM node:14-slim

USER node

RUN mkdir -p /home/node/app

WORKDIR /home/node/app

COPY --chown=node package*.json ./

RUN npm install

COPY --chown=node . .

RUN cd node_modules/@loopback/authentication-jwt && npm run build && cd .. && cd ..

RUN npm run build

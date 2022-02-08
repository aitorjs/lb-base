import {Client, expect} from '@loopback/testlab';
import jwt from 'jsonwebtoken';
import {LbBaseApplication} from '../../../index';
import {setupApplication, stopApplication} from '../test-helper';

describe('GET /users/me', () => {
  let app: LbBaseApplication;
  let client: Client;
  const randomNum = Math.floor(Math.random() * 10000000000 + 1);
  const url = '/users/me';
  const user = {
    email: `a@abc${randomNum}.com`,
    password: 'passpass',
  };
  let accessToken: string;
  let userId: number;

  before('setupApplication', async () => {
    ({app, client} = await setupApplication());

    const registeredUser = await client
      .post('/users/register')
      .send(user)
      .set('Accept', 'application/json')
      .expect(200);

    const loggedUser = await client
      .post('/users/login')
      .send(user)
      .set('Accept', 'application/json')
      .expect(200);

    accessToken = loggedUser.body.token;
    userId = registeredUser.body.id;
  });

  after(async () => {
    await stopApplication(app);
  });

  it('Invokes successfully', async () => {
    const response = await client
      .get(url)
      .send(user)
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(response.body.email).equal(user.email);
  });

  it('Fails without token', async () => {
    const response =
      '{"error":{"statusCode":401,"name":"UnauthorizedError","message":"Authorization header not found."}}';
    await client
      .get(url)
      .send(user)
      .set('Accept', 'application/json')
      .expect(401)
      .expect(response);
  });

  it('Fails with expired token', async () => {
    console.log('userId', userId);
    const response =
      '{"error":{"statusCode":401,"name":"UnauthorizedError","message":"Error verifying token : jwt expired"}}';
    const localUser = {
      name: ``,
      id: userId,
    };
    const localAccessToken = jwt.sign(
      localUser,
      process.env.JWT_ACCESS_SECRET!,
      {expiresIn: 0},
    );

    await client
      .get(url)
      .send(user)
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${localAccessToken}`)
      .expect(401)
      .expect(response);
  });
});

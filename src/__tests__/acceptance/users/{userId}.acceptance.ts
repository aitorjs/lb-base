import {Client, expect} from '@loopback/testlab';
import {LbBaseApplication} from '../../../index';
import {setupApplication, stopApplication} from '../test-helper';

describe('GET /users/{userId}', () => {
  let app: LbBaseApplication;
  let client: Client;
  const randomNum = Math.floor(Math.random() * 10000000000 + 1);
  const url = '/users/';
  const user = {
    email: `a@abc${randomNum}.com`,
    password: 'passpass',
  };
  let accessToken: string;
  let adminAccessToken: string;
  let userId: number;

  before('setupApplication', async () => {
    ({app, client} = await setupApplication());
    const admin = {
      email: process.env.ADMIN_EMAIL,
      password: process.env.ADMIN_PASS,
    };

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

    const adminUser = await client
      .post('/users/login')
      .send(admin)
      .set('Accept', 'application/json')
      .expect(200);

    accessToken = loggedUser.body.token;
    userId = registeredUser.body.id;
    adminAccessToken = adminUser.body.token;
  });

  after(async () => {
    await stopApplication(app);
  });

  it('Invokes successfully (from admin)', async () => {
    const response = await client
      .get(`${url}${userId}`)
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${adminAccessToken}`)
      .expect(200);

    expect(response.body.email).equal(user.email);
  });

  it(' Fails with user role valid token', async () => {
    const response =
      '{"error":{"statusCode":403,"name":"Error","message":"Access denied"}}';
    await client
      .get(`${url}${userId}`)
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(403)
      .expect(response);
  });
});

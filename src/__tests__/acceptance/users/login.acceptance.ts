import {Client, expect} from '@loopback/testlab';
import {LbBaseApplication} from '../../../index';
import {setupApplication, stopApplication} from '../test-helper';
describe('POST /users/login', () => {
  let app: LbBaseApplication;
  let client: Client;
  const randomNum = Math.floor(Math.random() * 10000000000 + 1);
  const url = '/users/login';
  const user = {
    email: `a@abc${randomNum}.com`,
    password: 'passpass',
  };

  before('setupApplication', async () => {
    ({app, client} = await setupApplication());

    await client
      .post('/users/register')
      .send(user)
      .set('Accept', 'application/json')
      .expect(200);
  });

  after(async () => {
    await stopApplication(app);
  });

  it('Invokes successfully', async () => {
    const loggedUser = await client
      .post(url)
      .send(user)
      .set('Accept', 'application/json')
      .expect(200);

    const hasProperty = Object.prototype.hasOwnProperty.call(
      loggedUser.body,
      'token',
    );
    expect(hasProperty).equal(true);
    expect(Object.keys(loggedUser.body).length).equal(1);
  });

  it('Fails with bad email', async () => {
    const response =
      '{"error":{"statusCode":401,"name":"UnauthorizedError","message":"Invalid email or password."}}';
    const newUser = Object.assign({}, user);
    newUser.email = 'asd@qdfg.com';

    await client
      .post(url)
      .send(newUser)
      .set('Accept', 'application/json')
      .expect(401)
      .expect(response);
  });

  it('Fails with bad password', async () => {
    const response =
      '{"error":{"statusCode":401,"name":"UnauthorizedError","message":"Invalid email or password."}}';
    const newUser = Object.assign({}, user);
    newUser.password = 'badpassword';

    await client
      .post(url)
      .send(newUser)
      .set('Accept', 'application/json')
      .expect(401)
      .expect(response);
  });
});

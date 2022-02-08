import {Client} from '@loopback/testlab';
import {LbBaseApplication} from '../../../index';
import {setupApplication, stopApplication} from '../test-helper';

describe('POST /users/register', () => {
  let app: LbBaseApplication;
  let client: Client;
  const randomNum = Math.floor(Math.random() * 10000000000 + 1);
  const url = '/users/register';
  const user = {
    email: `a@abc${randomNum}.com`,
    password: 'passpass',
  };

  before('setupApplication', async () => {
    ({app, client} = await setupApplication());
  });

  after(async () => {
    await stopApplication(app);
  });

  it('Invokes successfully', async () => {
    await client
      .post(url)
      .send(user)
      .set('Accept', 'application/json')
      .expect(200);
  });

  it('Fails with pass less than 8 characters', async () => {
    const response =
      '{"error":{"statusCode":422,"name":"UnprocessableEntityError","message":"password must be minimum 8 characters"}}';

    const newUser = Object.assign({}, user);
    newUser.password = 'passpas';

    await client
      .post(url)
      .send(newUser)
      .set('Accept', 'application/json')
      .expect(422)
      .expect(response);
  });

  it('Fails with duplicate email', async () => {
    const response =
      '{"error":{"statusCode":409,"name":"ConflictError","message":"Email value is already taken"}}';

    await client
      .post(url)
      .send(user)
      .set('Accept', 'application/json')
      .expect(409)
      .expect(response);
  });
});

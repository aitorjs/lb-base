import {Client} from '@loopback/testlab';
import {LbBaseApplication} from '../../../index';
import {setupApplication, stopApplication} from '../test-helper';

export declare type AdminToken = {
  token: string;
  userId: string;
};

describe('POST /users/changeRole', () => {
  let app: LbBaseApplication;
  let client: Client;
  const url = '/users/changeRole';
  const firstAdminToken: AdminToken = {token: '', userId: ''};

  before('setupApplication', async () => {
    ({app, client} = await setupApplication());
    const firstAdmin = {
      email: process.env.ADMIN_EMAIL,
      password: process.env.ADMIN_PASS,
    };

    const loggedFirstAdmin = await client
      .post('users/login')
      .send(firstAdmin)
      .set('Accept', 'application/json')
      .expect(200);

    const meFirstAdmin = await client
      .get('users/me')
      .set('Authorization', `Bearer ${loggedFirstAdmin.body.token}`)
      .set('Accept', 'application/json')
      .expect(200);

    firstAdminToken.token = loggedFirstAdmin.body.token;
    firstAdminToken.userId = meFirstAdmin.body.id;
  });

  after(async () => {
    await stopApplication(app);
  });

  it('Invokes successfully (first admin change a new user to admin)', async () => {
    const randomNum = Math.floor(Math.random() * 10000000000 + 1);
    const user = {
      email: `a@abc${randomNum}.com`,
      password: 'passpass',
    };

    const registeredUser = await client
      .post('users/register')
      .send(user)
      .set('Accept', 'application/json')
      .expect(200);

    const changeRoleRequest = {
      userId: registeredUser.body.id,
      newRole: 'admin',
    };
    await client
      .post(url)
      .send(changeRoleRequest)
      .set('Authorization', `Bearer ${firstAdminToken.token}`)
      .set('Accept', 'application/json')
      .expect(200);
  });

  it('Invokes successfully (admin change a new user to admin)', async () => {
    const randomNum = Math.floor(Math.random() * 10000000000 + 1);
    const user = {
      email: `a@abc${randomNum}.com`,
      password: 'passpass',
    };
    const admin = {
      email: `a@abcd${randomNum}.com`,
      password: 'passpass',
    };

    const registeredUser = await client
      .post('users/register')
      .send(user)
      .set('Accept', 'application/json')
      .expect(200);

    const registeredAdmin = await client
      .post('users/register')
      .send(admin)
      .set('Accept', 'application/json')
      .expect(200);

    const registeredAdminRequest = {
      userId: registeredAdmin.body.id,
      newRole: 'admin',
    };
    await client
      .post(url)
      .send(registeredAdminRequest)
      .set('Authorization', `Bearer ${firstAdminToken.token}`)
      .set('Accept', 'application/json')
      .expect(200);

    const loggedAdmin = await client
      .post('users/login')
      .send(admin)
      .set('Accept', 'application/json')
      .expect(200);

    const changeRoleRequest = {
      userId: registeredUser.body.id,
      newRole: 'admin',
    };
    console.log('changeRoleRequest', changeRoleRequest);
    await client
      .post(url)
      .send(changeRoleRequest)
      .set('Authorization', `Bearer ${loggedAdmin.body.token}`)
      .set('Accept', 'application/json')
      .expect(200);
  });

  it('Invokes successfully (admin change their role to user)', async () => {
    const randomNum = Math.floor(Math.random() * 10000000000 + 1);
    const admin = {
      email: `a@abcd${randomNum}.com`,
      password: 'passpass',
    };

    const registeredAdmin = await client
      .post('users/register')
      .send(admin)
      .set('Accept', 'application/json')
      .expect(200);

    const registeredAdminRequest = {
      userId: registeredAdmin.body.id,
      newRole: 'admin',
    };
    await client
      .post(url)
      .send(registeredAdminRequest)
      .set('Authorization', `Bearer ${firstAdminToken.token}`)
      .set('Accept', 'application/json')
      .expect(200);

    const loggedAdmin = await client
      .post('users/login')
      .send(admin)
      .set('Accept', 'application/json')
      .expect(200);

    const changeRoleRequest = {
      userId: registeredAdmin.body.id,
      newRole: 'user',
    };
    await client
      .post(url)
      .send(changeRoleRequest)
      .set('Authorization', `Bearer ${loggedAdmin.body.token}`)
      .set('Accept', 'application/json')
      .expect(200);
  });

  it('Fails when user token change their role to admin', async () => {
    const response =
      '{"error":{"statusCode":403,"name":"Error","message":"Access denied"}}';
    const randomNum = Math.floor(Math.random() * 10000000000 + 1);
    const user = {
      email: `a@abc${randomNum}.com`,
      password: 'passpass',
    };

    const registedUser = await client
      .post('users/register')
      .send(user)
      .set('Accept', 'application/json')
      .expect(200);

    const changeRoleRequest = {
      userId: registedUser.body.id,
      newRole: 'admin',
    };

    const loggedUser = await client
      .post('users/login')
      .send(user)
      .set('Accept', 'application/json')
      .expect(200);

    await client
      .post(url)
      .send(changeRoleRequest)
      .set('Authorization', `Bearer ${loggedUser.body.token}`)
      .set('Accept', 'application/json')
      .expect(403)
      .expect(response);
  });

  it('Fails when admin changes first root to user (downgrade first root role)', async () => {
    const response =
      '{"error":{"statusCode":401,"name":"UnauthorizedError","message":"Inmutable userId."}}';
    const randomNum = Math.floor(Math.random() * 10000000000 + 1);
    const admin = {
      email: `a@abcd${randomNum}.com`,
      password: 'passpass',
    };

    const registeredAdmin = await client
      .post('users/register')
      .send(admin)
      .set('Accept', 'application/json')
      .expect(200);

    const registeredAdminRequest = {
      userId: registeredAdmin.body.id,
      newRole: 'admin',
    };

    await client
      .post(url)
      .send(registeredAdminRequest)
      .set('Authorization', `Bearer ${firstAdminToken.token}`)
      .set('Accept', 'application/json')
      .expect(200);

    const loggedAdmin = await client
      .post('users/login')
      .send(admin)
      .set('Accept', 'application/json')
      .expect(200);

    const changeRoleRequest = {
      userId: firstAdminToken.userId,
      newRole: 'user',
    };
    await client
      .post(url)
      .send(changeRoleRequest)
      .set('Authorization', `Bearer ${loggedAdmin.body.token}`)
      .set('Accept', 'application/json')
      .expect(401)
      .expect(response);
  });

  it('Fails when admin changes other admin to user (downgrade first admin role)', async () => {
    const response =
      '{"error":{"statusCode":403,"name":"ForbiddenError","message":"Forbidden"}}';
    const randomNum1 = Math.floor(Math.random() * 10000000000 + 1);
    const admin1 = {
      email: `a@admin1${randomNum1}.com`,
      password: 'passpass',
    };
    const randomNum2 = Math.floor(Math.random() * 10000000000 + 1);
    const admin2 = {
      email: `a@admin2${randomNum2}.com`,
      password: 'passpass',
    };

    const registeredAdmin1 = await client
      .post('users/register')
      .send(admin1)
      .set('Accept', 'application/json')
      .expect(200);

    const registeredAdmin1Request = {
      userId: registeredAdmin1.body.id,
      newRole: 'admin',
    };

    const registeredAdmin2 = await client
      .post('users/register')
      .send(admin2)
      .set('Accept', 'application/json')
      .expect(200);

    const registeredAdmin2Request = {
      userId: registeredAdmin2.body.id,
      newRole: 'admin',
    };

    await client
      .post(url)
      .send(registeredAdmin1Request)
      .set('Authorization', `Bearer ${firstAdminToken.token}`)
      .set('Accept', 'application/json')
      .expect(200);

    await client
      .post(url)
      .send(registeredAdmin2Request)
      .set('Authorization', `Bearer ${firstAdminToken.token}`)
      .set('Accept', 'application/json')
      .expect(200);

    const loggedAdmin1 = await client
      .post('users/login')
      .send(admin1)
      .set('Accept', 'application/json')
      .expect(200);

    const changeRoleRequest = {
      userId: registeredAdmin2Request.userId,
      newRole: 'user',
    };
    await client
      .post(url)
      .send(changeRoleRequest)
      .set('Authorization', `Bearer ${loggedAdmin1.body.token}`)
      .set('Accept', 'application/json')
      .expect(403)
      .expect(response);
  });
});

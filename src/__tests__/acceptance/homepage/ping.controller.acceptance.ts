import {Client, expect} from '@loopback/testlab';
import {LbBaseApplication} from '../../..';
import {setupApplication, stopApplication} from '../test-helper';

describe('PingController', () => {
  let app: LbBaseApplication;
  let client: Client;

  before('setupApplication', async () => {
    ({app, client} = await setupApplication());
  });

  after(async () => {
    await stopApplication(app);
  });

  it('invokes GET /ping', async () => {
    const res = await client.get('/ping?msg=world').expect(200);
    expect(res.body).to.containEql({greeting: 'Hello from LoopBack'});
  });
});

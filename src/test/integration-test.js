const request = require('request-promise-native');
const expect = require('chai').expect;

const BASE_URL = process.env.BASE_URL;
const TEST_USERNAME = process.env.TEST_USERNAME;
const TEST_PASSWORD = process.env.TEST_PASSWORD;

const requestAuth = {
  user: TEST_USERNAME,
  pass: TEST_PASSWORD,
  sendImmediately: true
};

const requestOptions = {
  auth: requestAuth,
  resolveWithFullResponse: true
}

describe('jwt-service', () => {
  describe('/tokens/users', () => {
    it('returns 200 status when supplied with correct credentials', async() => {
    
      const response = await request.post(BASE_URL + '/tokens/users', requestOptions);
      expect(response.statusCode).to.be.equal(200);

    });
  });
});

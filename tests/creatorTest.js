import request from 'supertest';
import app from '../App.js';
import fs from 'fs';
import path from 'path';

describe('POST /api/creatoruser', () => {
  it('should create a new creator user and upload images to S3', async () => {
    const idFrontImagePath = path.join(__dirname, 'test-files', 'id-front.jpg');
    const idBackImagePath = path.join(__dirname, 'test-files', 'id-back.jpg');
    const profileImagePath = path.join(__dirname, 'test-files', 'profile.jpg');

    const idFrontImage = fs.createReadStream(idFrontImagePath);
    const idBackImage = fs.createReadStream(idBackImagePath);
    const profileImage = fs.createReadStream(profileImagePath);

    const res = await request(app)
      .post('/api/creatoruser')
      .field('userId', 'test-user-id')
      .field('fullName', 'Test Creator User')
      .field('idNumber', '123456789')
      .field('address', '123 Test Street')
      .attach('idFrontImage', idFrontImage)
      .attach('idBackImage', idBackImage)
      .attach('profileImage', profileImage);

    expect(res.statusCode).toBe(201);
    expect(res.body.message).toBe('Creator user created successfully');
    expect(res.body.usertype).toBe(1);
    expect(res.body.fullName).toBe('Test Creator User');
    expect(res.body.profileImage).toMatch(/https:\/\/ventieresources\.s3\.amazonaws\.com\/uploads\//);
  });
});
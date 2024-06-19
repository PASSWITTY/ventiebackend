import AWS from 'aws-sdk';
import fs from 'fs';


AWS.config.update({
  accessKeyId: 'YOUR_ACCESS_KEY_ID',
  secretAccessKey: 'YOUR_SECRET_ACCESS_KEY',
  region: 'YOUR_AWS_REGION',
});

const s3 = new AWS.S3();

const uploadToS3 = (file) => {
  const fileContent = fs.readFileSync(file.path);

  const params = {
    Bucket: 'YOUR_BUCKET_NAME',
    Key: `uploads/${file.originalname}`,
    Body: fileContent,
  };

  return s3.upload(params).promise();
};
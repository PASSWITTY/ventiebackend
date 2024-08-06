import dotenv from 'dotenv';
dotenv.config();

import fs from 'fs';
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

// Validate environment variables
if (!process.env.AWS_REGION) {
  console.error('Error: AWS_REGION is not set.');
  process.exit(1);
}
if (!process.env.AWS_ACCESS_KEY_ID) {
  console.error('Error: AWS_ACCESS_KEY_ID is not set.');
  process.exit(1);
}
if (!process.env.AWS_SECRET_ACCESS_KEY) {
  console.error('Error: AWS_SECRET_ACCESS_KEY is not set.');
  process.exit(1);
}
if (!process.env.S3_BUCKET_NAME) {
  console.error('Error: S3_BUCKET_NAME is not set.');
  process.exit(1);
}

const s3Client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

const uploadToS3 = async (file) => {
  // Check if the file exists
  if (!fs.existsSync(file.path)) {
    console.error('File not found:', file.path);
    throw new Error('File not found');
  }
  console.log('Uploading file:', file.path);

  // Read the file content
  let fileContent;
  try {
    fileContent = fs.readFileSync(file.path);
    console.log('File read successfully');
  } catch (err) {
    console.error('Error reading file:', err);
    throw err;
  }

  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: `uploads/${file.originalname}`,
    Body: fileContent,
  };

  const command = new PutObjectCommand(params);
  console.log('Sending upload command to S3');

  try {
    const response = await s3Client.send(command);
    console.log("File uploaded successfully:", response);
    
    // Construct and return the URL of the uploaded file
    const fileUrl = `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${params.Key}`;
    console.log("File URL:", fileUrl);
    return fileUrl;
  } catch (err) {
    console.error("Error uploading file:", err);
    throw err;
  }
};

export default uploadToS3;
import multer from 'multer';
import multerS3 from 'multer-s3';
import { S3Client } from '@aws-sdk/client-s3';

// AWS S3 Configuration 
const s3 = new S3Client({
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID, // Load from environment variables
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  },
  region: process.env.AWS_REGION // Set your S3 bucket region
});

const storage = multerS3({
  s3: s3,
  bucket: process.env.S3_BUCKET_NAME, // Your S3 bucket name
  acl: 'public-read',  //Make uploaded files publicly accessible
  contentType: multerS3.AUTO_CONTENT_TYPE, // Automatically detect content type
  key: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const extension = path.extname(file.originalname);
    cb(null, `uploads/${file.fieldname}-${uniqueSuffix}${extension}`);
  }
});

const upload = multer({ storage });

export default upload;

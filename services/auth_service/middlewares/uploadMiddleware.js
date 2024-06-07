import upload from '../../../utils/fileUpload.js';



const uploadMiddlewarePP = upload.single('profilePicture');


const uploadMiddlewareMM = upload.fields([
    { name: 'idFrontImage', maxCount: 1 },
    { name: 'idBackImage', maxCount: 1 },
    { name: 'profileImage', maxCount: 1 },
  ]);
  

export {uploadMiddlewarePP, uploadMiddlewareMM } ;
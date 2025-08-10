const { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
const fs = require('fs');

class S3Sync {
  constructor(region, accessKeyId, secretAccessKey) {
    this.s3 = new S3Client({
      region,
      credentials: {
        accessKeyId,
        secretAccessKey
      }
    });
  }

  async syncFile(filePath, bucketName, objectKey) {
    try {
      const localStats = fs.statSync(filePath);
      const localModified = localStats.mtime;
      
      let s3Modified;
      try {
        const headResponse = await this.s3.send(new HeadObjectCommand({
          Bucket: bucketName,
          Key: objectKey
        }));
        s3Modified = headResponse.LastModified;
      } catch (error) {
        s3Modified = null;
      }
      
      if (!s3Modified) {
        await this.uploadFile(filePath, bucketName, objectKey);
        return 'uploaded';
      } else if (s3Modified > localModified) {
        await this.downloadFile(bucketName, objectKey, filePath);
        return 'downloaded';
      } else if (localModified > s3Modified) {
        await this.uploadFile(filePath, bucketName, objectKey);
        return 'uploaded';
      } else {
        return 'in-sync';
      }
    } catch (error) {
      throw new Error(`Sync failed: ${error.message}`);
    }
  }

  async uploadFile(filePath, bucketName, objectKey) {
    const fileContent = fs.readFileSync(filePath);
    await this.s3.send(new PutObjectCommand({
      Bucket: bucketName,
      Key: objectKey,
      Body: fileContent
    }));
  }

  async downloadFile(bucketName, objectKey, localPath) {
    const response = await this.s3.send(new GetObjectCommand({
      Bucket: bucketName,
      Key: objectKey
    }));
    const fileContent = await response.Body.transformToByteArray();
    fs.writeFileSync(localPath, fileContent);
  }
}

module.exports = S3Sync;

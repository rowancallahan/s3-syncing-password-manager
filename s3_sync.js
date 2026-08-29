const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');

// Thin S3 wrapper. The decision about which side wins a sync belongs to the
// caller (main.js), which compares the logical vault timestamps stored inside
// the backup payload — never file modification times.
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

  // Returns the parsed JSON object, or null when the object does not exist.
  async downloadJson(bucketName, objectKey) {
    let response;
    try {
      response = await this.s3.send(new GetObjectCommand({
        Bucket: bucketName,
        Key: objectKey
      }));
    } catch (error) {
      if (error.name === 'NoSuchKey' || (error.$metadata && error.$metadata.httpStatusCode === 404)) {
        return null;
      }
      throw new Error(`Download failed: ${error.message}`);
    }
    const body = await response.Body.transformToString('utf8');
    return JSON.parse(body);
  }

  async uploadJson(bucketName, objectKey, payload) {
    try {
      await this.s3.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: objectKey,
        Body: JSON.stringify(payload, null, 2),
        ContentType: 'application/json'
      }));
    } catch (error) {
      throw new Error(`Upload failed: ${error.message}`);
    }
  }
}

module.exports = S3Sync;

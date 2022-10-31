import AWS from "aws-sdk";

const {
  AWS_REGION,
  AWS_IAM_USER,
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  AWS_BUCKET_NAME,
} = process.env;

AWS.config.update({
  region: AWS_REGION,
  credentials: {
    accessKeyId: AWS_ACCESS_KEY_ID,
    secretAccessKey: AWS_SECRET_ACCESS_KEY,
  },
});

class UploadImage {
  async upload(key, base64, mime) {
    try {
      const buffer = Buffer.from(
        base64.replace(/^data:image\/\w+;base64,/, ""),
        "base64"
      );
      const body = {
        Bucket: AWS_BUCKET_NAME,
        Key: key,
        Body: buffer,
        ContentEncoding: "base64",
        ContentType: mime || "image/jpeg",
        ACL: "public-read",
      };

      const s3 = new AWS.S3({
        apiVersion: "2006-03-01",
        region: AWS_REGION,
      });

      const data = await s3.upload(body).promise();
      return data;
    } catch (error) {
      return { error };
    }
  }

  async delete(key) {
    try {
      const body = {
        Bucket: AWS_BUCKET_NAME,
        Key: key,
      };

      const s3 = new AWS.S3({
        apiVersion: "2006-03-01",
        region: AWS_REGION,
      });

      const response = await s3.deleteObject(body).promise();

      return response;
    } catch (error) {
      return { error };
    }
  }
}

export default new UploadImage();

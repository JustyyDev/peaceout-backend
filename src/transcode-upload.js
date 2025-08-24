// transcode-upload.js
//
// PeaceOut: Video upload middleware with FFmpeg transcoding
//
// Usage: Import and use in your backend's upload route instead of multer-s3
//
// Requirements:
// - npm install fluent-ffmpeg @ffmpeg-installer/ffmpeg multer aws-sdk
// - Environment variables for your S3/e2 bucket (see main backend)
//
// Place this file in your backend source folder (e.g., src/)

const multer = require('multer');
const ffmpeg = require('fluent-ffmpeg');
const ffmpegInstaller = require('@ffmpeg-installer/ffmpeg');
const fs = require('fs');
const os = require('os');
const path = require('path');
const AWS = require('aws-sdk');

ffmpeg.setFfmpegPath(ffmpegInstaller.path);

const s3 = new AWS.S3({
  endpoint: process.env.E2_ENDPOINT, // e.g. 'https://n5g0.fra.idrivee2-53.com'
  accessKeyId: process.env.E2_KEY,
  secretAccessKey: process.env.E2_SECRET,
  region: process.env.E2_REGION,
  signatureVersion: 'v4',
  s3ForcePathStyle: true
});

// Multer storage to temp folder
const upload = multer({ dest: os.tmpdir() });

/**
 * Middleware: handles upload, transcode, and S3 upload.
 * Usage in your Express route:
 *   const { transcodeAndUpload } = require('./src/transcode-upload');
 *   app.post('/api/videos/upload', upload.single('video'), transcodeAndUpload, ...);
 */
function transcodeAndUpload(req, res, next) {
  if (!req.file) return res.status(400).json({ error: 'No video uploaded' });

  const inputPath = req.file.path;
  const outputPath = path.join(os.tmpdir(), 'out-' + Date.now() + '.mp4');

  // Transcode with FFmpeg to MP4/H.264/AAC
  ffmpeg(inputPath)
    .outputOptions([
      '-c:v libx264',
      '-preset veryfast',
      '-crf 23',
      '-c:a aac',
      '-b:a 128k',
      '-movflags +faststart'
    ])
    .output(outputPath)
    .on('end', async () => {
      // Upload to S3/e2
      const s3Key = (req.session?.userId || 'anon') + '-' + Date.now() + '.mp4';
      try {
        const s3result = await s3.upload({
          Bucket: process.env.E2_BUCKET || 'peaceout-uploads',
          Key: s3Key,
          Body: fs.createReadStream(outputPath),
          ContentType: 'video/mp4',
          ACL: 'public-read'
        }).promise();
        // Save S3 url to req for downstream handlers
        req.transcodedVideoUrl = s3result.Location;
        // Clean up temp files
        fs.unlinkSync(inputPath);
        fs.unlinkSync(outputPath);
        next();
      } catch (err) {
        fs.unlinkSync(inputPath);
        if (fs.existsSync(outputPath)) fs.unlinkSync(outputPath);
        res.status(500).json({ error: 'Failed to upload to storage', details: err.message });
      }
    })
    .on('error', err => {
      fs.unlinkSync(inputPath);
      if (fs.existsSync(outputPath)) fs.unlinkSync(outputPath);
      res.status(500).json({ error: 'Video transcoding failed', details: err.message });
    })
    .run();
}

module.exports = { upload, transcodeAndUpload };

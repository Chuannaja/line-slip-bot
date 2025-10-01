// line-bot.js
const line = require('@line/bot-sdk');
const express = require('express');
const pool = require('./db');
require('dotenv').config();
const multer = require('multer');
const fs = require('fs');

const router = express.Router();

// LINE config
const config = {
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.LINE_CHANNEL_SECRET
};

const client = new line.Client(config);

// Multer สำหรับเก็บสลิป
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Webhook LINE
router.post('/webhook', line.middleware(config), async (req, res) => {
  const events = req.body.events;
  try {
    for (const event of events) {
      // ตรวจสอบว่าเป็น message type image
      if (event.type === 'message' && event.message.type === 'image') {
        const messageId = event.message.id;
        const userId = event.source.userId;

        // ดึง content รูปจาก LINE
        const stream = await client.getMessageContent(messageId);
        const filepath = `uploads/${Date.now()}-${messageId}.jpg`;
        const writable = fs.createWriteStream(filepath);
        stream.pipe(writable);

        writable.on('finish', async () => {
          // บันทึกลง DB (ตัวอย่าง amount = 0, payment_date = วันนี้)
          const query = `
            INSERT INTO payments (user_id, amount, payment_date, slip_url)
            VALUES ($1, $2, CURRENT_DATE, $3) RETURNING *`;
          const values = [userId, 0, filepath];
          const result = await pool.query(query, values);

          // ตอบผู้ใช้ว่าอัพโหลดสำเร็จ
          await client.replyMessage(event.replyToken, {
            type: 'text',
            text: `ได้รับสลิปเรียบร้อย! ID: ${result.rows[0].id}`
          });
        });
      }
    }
    res.sendStatus(200);
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

module.exports = router;

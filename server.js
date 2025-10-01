// ====== REQUIRE (ไว้บนสุด) ======
require("dotenv").config();
const express = require("express");
const line = require("@line/bot-sdk");
const { Pool } = require("pg");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const vision = require("@google-cloud/vision");
const expressLayouts = require("express-ejs-layouts");

// ถ้ามีใบเสร็จ JPEG
const ejs = require("ejs");
const puppeteer = require("puppeteer-core");
const chromium = require("@sparticuz/chromium");


// ← เพิ่มแค่นี้พอ (อย่าใช้ก่อนสร้าง app)
const session = require("express-session");
const bcrypt  = require("bcrypt");

// ====== APP (ต้องมาก่อน app.use(...)) ======
const app = express();

// ==== VIEW CONFIG ====
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(expressLayouts);
app.set("layout", "layout");

// ==== LINE CONFIG ====
const lineConfig = {
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.LINE_CHANNEL_SECRET,
};
const client = new line.Client(lineConfig);

function wait(ms){ return new Promise(r => setTimeout(r, ms)); }

async function safePush(to, message, retries = 3) {
  for (let i = 0; i <= retries; i++) {
    try {
      await client.pushMessage(to, message);
      return true;
    } catch (err) {
      const code = err?.statusCode || err?.originalError?.response?.status;
      const data = err?.originalError?.response?.data;
      console.error("LINE push error:", code, data || err.message);

      // ถ้าเป็น 429 ให้ถอยหลัง (backoff) แล้วลองใหม่
      if (code === 429 && i < retries) {
        await wait(300 * Math.pow(2, i)); // 300ms → 600ms → 1200ms
        continue;
      }
      // error อื่น ๆ หรือรีทรายครบ → เลิก
      return false;
    }
  }
}


// ==== DB CONFIG ====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// 🟢 เพิ่ม: สร้างตาราง Log
async function ensurePaymentLogsTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS payment_logs (
        id SERIAL PRIMARY KEY,
        payment_id INT NOT NULL REFERENCES payments(id) ON DELETE CASCADE,
        action VARCHAR(50) NOT NULL,
        old_data JSONB,
        new_data JSONB,
        actor_id INT,
        actor_name VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log("✅ payment_logs table ready");
  } catch (err) {
    console.error("❌ Init payment_logs error:", err);
  }
}
ensurePaymentLogsTable();

// 🟢 helper สำหรับเขียน Log
async function logPaymentAction({ paymentId, action, oldData=null, newData=null, actorId=null, actorName=null }) {
  try {
    await pool.query(
      `INSERT INTO payment_logs (payment_id, action, old_data, new_data, actor_id, actor_name)
       VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6)`,
      [paymentId, action, oldData ? JSON.stringify(oldData) : null, newData ? JSON.stringify(newData) : null, actorId, actorName]
    );
  } catch (err) {
    console.error("❌ logPaymentAction error:", err);
  }
}


// ==== INIT USERS TABLE ====
async function initTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log("✅ Users table ready");
  } catch (err) {
    console.error("❌ Init table error:", err);
  }
}
//initTables();


// ==== GOOGLE VISION CLIENT ====
const visionClient = new vision.ImageAnnotatorClient();

// ==== UPLOAD DIR ====
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ==== WEBHOOK (ต้องมาก่อน body parser อื่นๆ) ====
app.post("/webhook", line.middleware(lineConfig), async (req, res) => {
  try {
    const events = req.body.events;
    console.log("👉 Incoming events:", JSON.stringify(events, null, 2));

    await Promise.all(events.map(handleEvent));
    res.status(200).end();
  } catch (err) {
    console.error("❌ Webhook Error:", err);
    res.status(500).end();
  }
});

// ==== MIDDLEWARE อื่น ๆ (หลัง webhook) ====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(uploadDir));
app.use(express.static(path.join(__dirname, "public")));

// 👇 ใส่ต่อจากนี้
app.use(session({
  secret: process.env.SESSION_SECRET || "mySecretKey",
  resave: false,
  saveUninitialized: false
}));

// ให้ EJS มองเห็นข้อมูลผู้ใช้ที่ล็อกอิน
app.use((req, res, next) => {
  res.locals.user = req.session.user || null; // ใช้ใน view ได้เป็นตัวแปร user
  next();
});


// 🟢 กัน error เวลา req.session ไม่มี
function requireLogin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.redirect("/login");
  }
  next();
}

// ==== OCR Function ====
async function extractAmountFromSlip(filePath) {
  try {
    const [result] = await visionClient.textDetection(filePath);
    const detections = result.textAnnotations;
    if (!detections || detections.length === 0) return null;

    const text = detections[0].description;
    console.log("📄 OCR Text:", text);

    // Regex หาเงิน เช่น 1,200.00 หรือ 500.00
    const match = text.match(/([0-9,]+\.\d{2})/);
    return match ? parseFloat(match[1].replace(/,/g, "")) : null;
  } catch (err) {
    console.error("❌ OCR Error:", err);
    return null;
  }
}

// ==== EVENT HANDLER ====
async function handleEvent(event) {
  if (event.type === "message" && event.message.type === "image") {
    return new Promise(async (resolve, reject) => {
      const messageId = event.message.id;
      const userId = event.source.userId || "unknown";
      const baseUrl = process.env.PUBLIC_URL || "http://localhost:3000";

      const stream = await client.getMessageContent(messageId);
      const filePath = path.join(uploadDir, `${messageId}.jpg`);
      const writable = fs.createWriteStream(filePath);
      stream.pipe(writable);

      writable.on("finish", async () => {
        try {
          const amount = await extractAmountFromSlip(filePath);
          const result = await pool.query(
            `INSERT INTO payments (user_id, slip_url, amount) 
             VALUES ($1, $2, $3) RETURNING id`,
            [userId, `/uploads/${messageId}.jpg`, amount || 0]
          );
          const paymentId = result.rows[0].id;

          await client.replyMessage(event.replyToken, {
            type: "text",
            text: `✅ ระบบได้รับสลิปแล้ว!\n\n📝 กรอกข้อมูลเพิ่มเติม:\n${baseUrl}/form/${paymentId}`,
          });

          if (process.env.LINE_GROUP_ID) {
            await client.pushMessage(process.env.LINE_GROUP_ID, {
              type: "text",
              text:
                `📌 รับสลิปแล้ว! เลขที่อ้างอิง: ${paymentId}\n` +
                `ยอดเงิน: ${amount ? amount.toFixed(2) + " บาท" : "ไม่พบ"}\n` +
                `ไฟล์สลิป: ${baseUrl}/uploads/${messageId}.jpg\n\n` +
                `🔗 Dashboard: ${baseUrl}/admin/dashboard`,
            });
          }
          resolve();
        } catch (e) { reject(e); }
      });
      writable.on("error", reject);
    });
  }

  if (event.type === "message" && event.message.type === "text") {
    return client.replyMessage(event.replyToken, {
      type: "text",
      text: `คุณพิมพ์ว่า: ${event.message.text}`,
    });
  }
}

/// GET: หน้า Login
app.get("/login", (req, res) => {
  res.render("login", { title: "เข้าสู่ระบบ", error: null });
});

// POST: ตรวจ user/password
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
    const user = result.rows[0];
    if (!user) return res.render("login", { title: "เข้าสู่ระบบ", error: "❌ ไม่พบผู้ใช้งาน" });

    // รองรับ user เก่า (plain-text) + migrate อัตโนมัติ
    let ok = false;
    try { ok = await bcrypt.compare(password, user.password); } catch (_) { ok = false; }
    if (!ok && password === user.password) {
      ok = true;
      const hash = await bcrypt.hash(password, 10);
      await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, user.id]);
    }
    if (!ok) return res.render("login", { title: "เข้าสู่ระบบ", error: "❌ รหัสผ่านไม่ถูกต้อง" });

    req.session.user = {
						  id: Number(user.id),   // ✅ แปลงเป็น integer
						  username: user.username,
						  display_name: user.display_name || user.username,
						  role: user.role || "User"  // 🟢 เพิ่ม
					  };

    res.redirect("/admin/dashboard");
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});

// GET: ออกจากระบบ
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// 🟢 GET: หน้าแก้ไขข้อมูล
app.get("/admin/edit/:id", requireLogin, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const result = await pool.query("SELECT * FROM payments WHERE id=$1", [id]);
    if (!result.rows.length) {
      return res.status(404).send("ไม่พบข้อมูลที่จะทำการแก้ไข");
    }
    const payment = result.rows[0];
    res.render("edit", { payment, title: "แก้ไขข้อมูลการชำระเงิน" });
  } catch (err) {
    console.error("❌ edit GET error:", err);
    res.status(500).send("❌ Error: " + err.message);
  }
});


// ==== ADMIN MANAGE PAGE ====
app.get("/admin/manage", requireLogin, async (req, res) => {
  try {    
    // 🔧 เปลี่ยน: ดึง role ออกมาด้วย
    const result = await pool.query("SELECT id, username, display_name, role, created_at FROM users ORDER BY id ASC");
    res.render("admin", { 
      title: "จัดการระบบ", 
      query: req.query, 
      users: result.rows   // 🟢 ส่ง users ไปยัง view
    });
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});

// ==== ADD USER ====
app.post("/admin/users/add", requireLogin, async (req, res) => {
  try {
    // 🔧 เปลี่ยน: รับ role มาด้วย (ค่า: Full Control / Admin / User)
    const { username, display_name, password, role } = req.body;
    const hash = await bcrypt.hash(password, 10);    
    // 🔧 เปลี่ยน: บันทึก role ลง DB
    await pool.query(
      "INSERT INTO users (username, display_name, password, role) VALUES ($1, $2, $3, $4)",
      [username, display_name, hash, role || "User"]
    );
    res.redirect("/admin/manage?success=1");
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});

// 🟢 NEW: ลบ User (ได้เฉพาะผู้ที่มี role = Full Control)
app.post("/admin/delete-user/:id", requireLogin, async (req, res) => {
  try {
    const currentUser = req.session.user;
    const targetId = parseInt(req.params.id, 10);;

    // จำกัดเฉพาะ Full Control
    if (!currentUser || currentUser.role !== "Full Control") {
      return res.status(403).send("❌ คุณไม่มีสิทธิ์ลบ User");
    }

    // กันลบตัวเอง (ป้องกันล็อกเอาท์ไม่เหลือ Full Control)
    if (String(currentUser.id) === String(targetId)) {
      return res.status(400).send("❌ ไม่สามารถลบ User ของตนเองได้");
    }

    await pool.query("DELETE FROM users WHERE id=$1", [targetId]);
    req.session.message = "✅ ลบ User สำเร็จ";
    return res.redirect("/admin/manage");
  } catch (err) {
    console.error("❌ delete-user error:", err);
    return res.status(500).send("❌ Error: " + err.message);
  }
});


// 🟢 GET: หน้า Log
app.get("/admin/logs", requireLogin, async (req, res) => {
  try {
    const { payment_id } = req.query;
    let logs;

    if (payment_id) {
      const result = await pool.query(
        `SELECT l.*, p.first_name, p.last_name 
         FROM payment_logs l
         LEFT JOIN payments p ON l.payment_id = p.id
         WHERE l.payment_id = $1
         ORDER BY l.created_at DESC`,
        [payment_id]
      );
      logs = result.rows;
    } else {
      const result = await pool.query(
        `SELECT l.*, p.first_name, p.last_name 
         FROM payment_logs l
         LEFT JOIN payments p ON l.payment_id = p.id
         ORDER BY l.created_at DESC
         LIMIT 100`
      );
      logs = result.rows;
    }

    res.render("logs", { 
      logs, 
      title: "ประวัติการทำรายการ", 
      user: req.session.user || null,
      payment_id: payment_id || ""   // ส่งไปเผื่อเติมค่าใน input
    });
  } catch (err) {
    console.error("❌ logs error:", err);
    res.status(500).send("❌ Error: " + err.message);
  }
});
// 🟢 หน้า การจัดการข้อมูล
app.get("/admin/data-management", requireLogin, (req, res) => {
  res.render("data-management", { 
    title: "การจัดการข้อมูล", 
    user: req.session.user || null 
  });
});

// 🟢 ลบข้อมูลทั้งหมด (ยกเว้น users)
app.post("/admin/clear-data", requireLogin, async (req, res) => {
  const { confirm_key } = req.body;

  if (confirm_key !== "LL68") {
    return res.status(400).send("❌ Key ไม่ถูกต้อง");
  }

  try {
    // ดึงรายชื่อตารางทั้งหมดใน public schema
    const tables = await pool.query(`
      SELECT tablename 
      FROM pg_tables 
      WHERE schemaname='public'
    `);

    for (const row of tables.rows) {
      if (row.tablename !== "users") {
        await pool.query(`TRUNCATE TABLE ${row.tablename} RESTART IDENTITY CASCADE`);
      }
    }

    // ✅ หลังลบเสร็จ
    req.session.message = "✅ ลบข้อมูลทั้งหมดสำเร็จ";
    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error("❌ clear-data error:", err);
    res.status(500).send("❌ Error: " + err.message);
  }
});
// 🟢 ลบ Logs ทั้งหมด
app.post("/admin/clear-logs", requireLogin, async (req, res) => {
  const { confirm_key } = req.body;

  if (confirm_key !== "LL68") {
    return res.status(400).send("❌ Key ไม่ถูกต้อง");
  }

  try {
    await pool.query(`TRUNCATE TABLE payment_logs RESTART IDENTITY CASCADE`);
    req.session.message = "✅ ลบ Logs ทั้งหมดสำเร็จ";
    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error("❌ clear-logs error:", err);
    res.status(500).send("❌ Error: " + err.message);
  }
});
const ExcelJS = require("exceljs");

// 🟢 Export Excel
app.get("/admin/export-excel", requireLogin, async (req, res) => {
  try {
    const { status, from, to } = req.query;

    // กรองข้อมูลตาม filter
    let sql = "SELECT id, first_name, last_name, phone, payment_type, amount, status, created_at FROM payments WHERE 1=1";
    const params = [];

    if (status) {
      params.push(status);
      sql += ` AND status=$${params.length}`;
    }
    if (from) {
      params.push(from);
      sql += ` AND created_at >= $${params.length}`;
    }
    if (to) {
      params.push(to);
      sql += ` AND created_at <= $${params.length}`;
    }

    sql += " ORDER BY created_at DESC";

    const result = await pool.query(sql, params);
    const rows = result.rows;

    // สร้างไฟล์ Excel
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet("Payments");

    // Header
    sheet.columns = [
      { header: "เลขที่", key: "id", width: 10 },
      { header: "ชื่อ", key: "first_name", width: 20 },
      { header: "นามสกุล", key: "last_name", width: 20 },
      { header: "เบอร์โทร", key: "phone", width: 15 },
      { header: "ประเภทการชำระ", key: "payment_type", width: 25 },
      { header: "ยอดเงิน", key: "amount", width: 15 },
      { header: "สถานะ", key: "status", width: 15 },
      { header: "วันที่สร้าง", key: "created_at", width: 25 }
    ];

    // Rows
    rows.forEach(r => {
      sheet.addRow({
        id: r.id,
        first_name: r.first_name,
        last_name: r.last_name,
        phone: r.phone,
        payment_type: r.payment_type,
        amount: r.amount,
        status: r.status,
        created_at: new Date(r.created_at).toLocaleString("th-TH")
      });
    });

    // ส่งไฟล์ให้โหลด
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", "attachment; filename=payments.xlsx");

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error("❌ export-excel error:", err);
    res.status(500).send("❌ Error: " + err.message);
  }
});



// ==== RESET DATABASE ====
app.post("/admin/reset-db", requireLogin, async (req, res) => {
  try {
    await pool.query("TRUNCATE TABLE payments RESTART IDENTITY CASCADE");
    res.redirect("/admin/dashboard?reset_success=1"); // ส่ง flag ไป Dashboard
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});

// ==== FORM ROUTE ====
app.get("/form/:id", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM payments WHERE id=$1", [
      parseInt(req.params.id, 10),
    ]);
    const payment = result.rows[0];
    res.render("form", { payment });
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});

app.post("/form/:id", upload.none(), async (req, res) => {
  const { first_name, last_name, phone, payment_type, house_no, village_no, province, district, subdistrict } = req.body;
  const id = parseInt(req.params.id, 10);

  // 🟢 รวมที่อยู่ให้ครบ
  const address = `${house_no ? house_no : ''} ${village_no ? 'หมู่ ' + village_no : ''} ต.${subdistrict} อ.${district} จ.${province}`;

  try {
    const result = await pool.query(
      `UPDATE payments 
       SET first_name=$1, last_name=$2, address=$3, phone=$4, payment_type=$5
       WHERE id=$6 RETURNING *`,
      [first_name, last_name, address.trim(), phone, payment_type, id]
    );

    const payment = result.rows[0];
    const baseUrl = process.env.PUBLIC_URL || "http://localhost:3000";

    // ผู้ส่ง (มี userId และขึ้นต้นด้วย U เท่านั้น)
	if (payment.user_id && payment.user_id.startsWith("U")) {
	  await safePush(payment.user_id, {
		type: "text",
		text:
		  `✅ ส่งข้อมูลเรียบร้อยแล้ว\n\n` +
		  `ชื่อ: ${payment.first_name} ${payment.last_name}\n` +
		  `เบอร์โทรศัพท์: ${payment.phone}\n` +
		  `รายการชำระ: ${payment.payment_type}\n` +
		  `ยอดเงิน: ${payment.amount ? Number(payment.amount).toFixed(2) + " บาท" : "ไม่พบ"}\n` +
		  `สถานะ: รอดำเนินการ`
	  });
	}

	// กลุ่ม
	if (process.env.LINE_GROUP_ID) {
	  const baseUrl = process.env.PUBLIC_URL || "http://localhost:3000";
	  await safePush(process.env.LINE_GROUP_ID, {
		type: "text",
		text:
		  `📌 รับสลิปแล้ว! เลขที่อ้างอิง: ${payment.id}\n` +
		  `ชื่อ: ${payment.first_name} ${payment.last_name}\n` +
		  `เบอร์โทรศัพท์: ${payment.phone}\n` +
		  `ที่อยู่: ${payment.address}\n` +
		  `รายการชำระ: ${payment.payment_type}\n` +
		  `ยอดเงิน: ${payment.amount ? Number(payment.amount).toFixed(2) + " บาท" : "ไม่พบ"}\n` +
		  `ไฟล์สลิป: ${baseUrl}${payment.slip_url}\n\n` +
		  `🔗 Dashboard: ${baseUrl}/admin/dashboard`
	  });
	}

	// ✅ ไม่ว่าการ push จะสำเร็จหรือไม่ ให้ตอบกลับผู้ใช้หน้าเว็บเป็น 200 เสมอ
	return res.send("✅ บันทึกข้อมูลเรียบร้อยแล้ว ขอบคุณครับ");

  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});

// ==== DASHBOARD ROUTE (ค้นหา) ====
app.get("/admin/dashboard", requireLogin, async (req, res) => {
  try {
    const { from, to, id, first_name, address, phone, status, payment_type } = req.query;

    let conditions = [];
    let values = [];
    let i = 1;

    if (from) {
      conditions.push(`p.created_at::date >= $${i++}`);
      values.push(from);
    }
    if (to) {
      conditions.push(`p.created_at::date <= $${i++}`);
      values.push(to);
    }
    if (id && !isNaN(id)) {
      conditions.push(`p.id = $${i++}`);
      values.push(Number(id));
    }
    if (first_name) {
      conditions.push(`p.first_name ILIKE $${i++}`);
      values.push(`%${first_name}%`);
    }
    if (address) {
      conditions.push(`p.address ILIKE $${i++}`);
      values.push(`%${address}%`);
    }
    if (phone) {
      conditions.push(`p.phone ILIKE $${i++}`);
      values.push(`%${phone}%`);
    }
    if (status) {
      conditions.push(`p.status = $${i++}`);
      values.push(status);
    }
    if (payment_type) {
      conditions.push(`p.payment_type = $${i++}`);
      values.push(payment_type);
    }

    let sql = `
			   SELECT p.*,
					  COALESCE(u.display_name, u.username) AS operator_name
			   FROM payments p
			   LEFT JOIN users u ON u.id = p.status_changed_by
			 `;

    if (conditions.length > 0) {
      sql += " WHERE " + conditions.join(" AND ");
    }
    sql += " ORDER BY p.id DESC";

    const result = await pool.query(sql, values);

    res.render("dashboard", {
      payments: result.rows,
      query: req.query,
      title: "รายการชำระเงิน"
    });
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});


app.post("/admin/update/:id", requireLogin, async (req, res) => {
  const { status, reject_reason } = req.body;
  const id = parseInt(req.params.id, 10);

  const statusText =
    status === "approved" ? "อนุมัติ" :
    status === "rejected" ? "ไม่อนุมัติ" : "รอดำเนินการ";

  // ผู้ปฏิบัติ
  const actorId = req.session?.user?.id ? Number(req.session.user.id) : null;
  const actorName = req.session?.user?.display_name || req.session?.user?.username || "ไม่ทราบผู้ใช้";

  try {
    // ⬇️ (เพิ่ม) ดึงข้อมูลเดิมไว้เขียน Log
    const oldQ = await pool.query("SELECT * FROM payments WHERE id=$1", [id]);
    if (!oldQ.rows.length) return res.status(404).send("ไม่พบข้อมูล");
    const oldData = oldQ.rows[0];

    // อัปเดตสถานะ + ผู้กด + เวลา
    const result = await pool.query(
      `UPDATE payments 
       SET status=$1, 
           reject_reason=$2,
           status_changed_by=$3,
           status_changed_at=NOW()
       WHERE id=$4
       RETURNING *`,
      [status, status === "rejected" ? reject_reason : null, actorId, id]
    );
    const payment = result.rows[0];   

    const baseUrl = process.env.PUBLIC_URL || "http://localhost:3000";

    // === ส่วนเดิมของคุณ: ถ้าอนุมัติ → เรนเดอร์ใบเสร็จ + ส่ง LINE ===
    if (status === "approved" && payment) {
      const receiptHtml = await ejs.renderFile(
        path.join(__dirname, "views/receipt.ejs"),
        { 
          payment,
          user: req.session.user || null,
          title: "ใบเสร็จรับเงิน"
        }
      );

      const browser = await puppeteer.launch({
		  args: chromium.args,
		  defaultViewport: chromium.defaultViewport,
		  executablePath: await chromium.executablePath(),
		  headless: chromium.headless,
		});

      const page = await browser.newPage();
      await page.setContent(receiptHtml, { waitUntil: "networkidle0" });

      const receiptDir = path.join(uploadDir, "receipts");
      if (!fs.existsSync(receiptDir)) fs.mkdirSync(receiptDir);

      const receiptPath = path.join(receiptDir, `receipt-${payment.id}.jpg`);
      await page.screenshot({ path: receiptPath, type: "jpeg", fullPage: true });
      await browser.close();

      const receiptUrl = `${baseUrl}/uploads/receipts/receipt-${payment.id}.jpg`;

      if (payment.user_id && payment.user_id.startsWith("U")) {
        await client.pushMessage(payment.user_id, {
          type: "image",
          originalContentUrl: receiptUrl,
          previewImageUrl: receiptUrl
        });

        await client.pushMessage(payment.user_id, {
          type: "text",
          text:
`✅ การชำระเงิน #${id}  
🎉 สถานะ: อนุมัติเรียบร้อยแล้ว  

👤 ผู้ตรวจสอบ: ${actorName}  
📄 ใบเสร็จถูกส่งให้เรียบร้อย`
        });
      }
    } else {
      // === ส่วนเดิมของคุณ: แจ้งผู้ส่งสลิปกรณีไม่อนุมัติ/อื่น ๆ ===
      if (payment.user_id && payment.user_id.startsWith("U")) {
        let message = "";
        if (status === "rejected" && payment.reject_reason) {
message =
`⚠️ การชำระเงิน #${id}  
❌ สถานะ: ไม่อนุมัติ  

👤 ผู้ตรวจสอบ: ${actorName}  
📝 เหตุผล: ${payment.reject_reason}`;
        } else {
message =
`ℹ️ การชำระเงิน #${id}  
📌 สถานะ: ${statusText}  

👤 ผู้ตรวจสอบ: ${actorName}`;
        }
        await client.pushMessage(payment.user_id, { type: "text", text: message });
      }
    }

    // === ส่วนเดิมของคุณ: แจ้งกลุ่ม LINE ===
    if (process.env.LINE_GROUP_ID) {
      let message = "";
      if (status === "rejected" && payment.reject_reason) {
message =
`⚠️ การชำระเงิน #${id}  
❌ สถานะ: ไม่อนุมัติ  

👤 ผู้ตรวจสอบ: ${actorName}  
📝 เหตุผล: ${payment.reject_reason}`;
      } else if (status === "approved") {
message =
`✅ การชำระเงิน #${id}  
🎉 สถานะ: อนุมัติเรียบร้อยแล้ว  

👤 ผู้ตรวจสอบ: ${actorName}`;
      } else {
message =
`ℹ️ การชำระเงิน #${id}  
📌 สถานะ: ${statusText}  

👤 ผู้ตรวจสอบ: ${actorName}`;
      }
      await client.pushMessage(process.env.LINE_GROUP_ID, { type: "text", text: message });
    }

    res.redirect("/admin/dashboard");
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});
// 🟢 GET: ใบเสร็จรับเงิน
app.get("/admin/receipt/:id", requireLogin, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const result = await pool.query("SELECT * FROM payments WHERE id=$1", [id]);
    if (!result.rows.length) return res.status(404).send("ไม่พบข้อมูลใบเสร็จ");
    const payment = result.rows[0];

    res.render("receipt", { 
      payment,
      title: "ใบเสร็จรับเงิน",
      user: req.session.user || null   // 🟢 ส่ง user ให้ layout ใช้
    });
  } catch (err) {
    console.error("❌ receipt error:", err);
    res.status(500).send("❌ Error: " + err.message);
  }
});


// 🟢 เพิ่ม: แก้ไขข้อมูลการชำระเงิน (ADMIN)
// รับฟิลด์ที่แก้ไขผ่าน form: first_name, last_name, address, phone, payment_type, amount (ถ้ามี)
// 🟢 แก้ไขข้อมูลการชำระเงิน (ADMIN)
app.post("/admin/edit/:id", requireLogin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const actorId = req.session?.user?.id ? Number(req.session.user.id) : null;
  const actorName = req.session?.user?.display_name || req.session?.user?.username || "ไม่ทราบผู้ใช้";

  try {
    // 1) ดึงข้อมูลเก่า
    const oldQ = await pool.query("SELECT * FROM payments WHERE id=$1", [id]);
    if (!oldQ.rows.length) return res.status(404).send("ไม่พบข้อมูลที่ต้องการแก้ไข");
    const oldData = oldQ.rows[0];

    // 2) เตรียม payload
    const fields = ["first_name", "last_name", "address", "phone", "payment_type", "amount"];
    const payload = {};
    for (const f of fields) payload[f] = (req.body[f] ?? oldData[f]);

    if (payload.amount !== null && payload.amount !== undefined && payload.amount !== "") {
      const num = Number(payload.amount);
      if (!isNaN(num)) payload.amount = num;
      else payload.amount = oldData.amount;
    }

    // 3) UPDATE
    const upd = await pool.query(
      `UPDATE payments
         SET first_name=$1,
             last_name=$2,
             address=$3,
             phone=$4,
             payment_type=$5,
             amount=$6
       WHERE id=$7
       RETURNING *`,
      [payload.first_name, payload.last_name, payload.address, payload.phone, payload.payment_type, payload.amount, id]
    );
    const newData = upd.rows[0];

    // 4) หาค่าที่เปลี่ยนจริง ๆ
    const changedOld = {};
    const changedNew = {};
    for (let key of fields) {
      if (oldData[key] != newData[key]) {
        changedOld[key] = oldData[key];
        changedNew[key] = newData[key];
      }
    }

    // 5) ถ้ามีการแก้ไข → log
    if (Object.keys(changedOld).length > 0) {
      await logPaymentAction({
        paymentId: Number(id),
        action: "edit",
        oldData: changedOld,
        newData: changedNew,
        actorId,
        actorName
      });
    }

    return res.redirect("/admin/dashboard?edited_id=" + id);
  } catch (err) {
    console.error("❌ edit error:", err);
    return res.status(500).send("❌ Error: " + err.message);
  }
});


// 🟢 Route ลบ
app.post("/admin/delete/:id", requireLogin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const actorId = req.session?.user?.id ? Number(req.session.user.id) : null;
  const actorName = req.session?.user?.display_name || req.session?.user?.username || "ไม่ทราบผู้ใช้";

  try {
    const oldQ = await pool.query("SELECT * FROM payments WHERE id=$1", [id]);
    if (!oldQ.rows.length) return res.status(404).send("ไม่พบข้อมูลที่จะลบ");
    const oldData = oldQ.rows[0];

    // ⬇️ บันทึก log ก่อนลบ
    await logPaymentAction({ 
      paymentId: Number(id), 
      action: "delete", 
      oldData, 
      newData: null, 
      actorId, 
      actorName 
    });

    // ⬇️ ค่อยลบ record
    await pool.query("DELETE FROM payments WHERE id=$1", [id]);

    res.redirect("/admin/dashboard?deleted_id=" + id);
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});




// ==== SUMMARY ROUTE ====
app.get("/admin/summary", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT TO_CHAR(created_at, 'YYYY-MM-DD') AS day, SUM(amount) as total
      FROM payments
      WHERE status='approved'
      GROUP BY day
      ORDER BY day ASC
    `);

    const labels = result.rows.map(r => r.day);
    const data = result.rows.map(r => Number(r.total));

    res.render("summary", { labels, data, title: "สรุปยอด" });
  } catch (err) {
    res.status(500).send("❌ Error: " + err.message);
  }
});
// 🟢 Route หน้าแรก (เพิ่มใหม่)
// ใส่ก่อน START SERVER
app.get("/", (req, res) => {
  // ถ้ายังไม่ได้ login → redirect ไป /login
  if (!req.session || !req.session.user) {
    return res.redirect("/login");
  }
  // ถ้า login แล้ว → redirect ไป Dashboard
  return res.redirect("/admin/dashboard");
});

// ==== START SERVER ====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

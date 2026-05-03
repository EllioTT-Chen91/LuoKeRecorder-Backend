require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3001;
const cors = require("cors");

app.use(cors());
app.use(express.json());
// 解决 CORS 401 的关键配置
app.use(
  cors({
    origin: true, // 允许所有来源，或指定你的 frontend 域名
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// 连接 Neon PostgreSQL
const pool = new Pool({
  connectionString: process.env.NEON_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// JWT 验证中间件
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "未登录" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "登录已过期" });
    req.user = user;
    next();
  });
}

// --- 将以下路由添加到你的 server.js 中 ---

// 获取当前用户的所有捕获记录
app.get("/api/hunts", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM roco_hunt_records WHERE user_id = $1 ORDER BY last_modified DESC",
      [req.user.id],
    );
    const hunts = result.rows.map((row) => ({
      ...row.captures,
      id: row.record_id,
    }));
    res.json(hunts);
  } catch (err) {
    res.status(500).json({ error: "拉取记录失败" });
  }
});

// 新增记录
app.post("/api/hunts", authenticateToken, async (req, res) => {
  const hunt = req.body;
  try {
    await pool.query(
      "INSERT INTO roco_hunt_records (user_id, record_id, target, captures) VALUES ($1, $2, $3, $4)",
      [req.user.id, hunt.id, hunt.petName, hunt],
    );
    res.sendStatus(201);
  } catch (err) {
    res.status(500).json({ error: "同步失败" });
  }
});

// 更新记录
app.put("/api/hunts/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const hunt = req.body;
  try {
    await pool.query(
      "UPDATE roco_hunt_records SET captures = $1, target = $2, last_modified = NOW() WHERE user_id = $3 AND record_id = $4",
      [hunt, hunt.petName, req.user.id, id],
    );
    res.sendStatus(200);
  } catch (err) {
    res.status(500).json({ error: "更新失败" });
  }
});

// 删除记录
app.delete("/api/hunts/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      "DELETE FROM roco_hunt_records WHERE user_id = $1 AND record_id = $2",
      [req.user.id, id],
    );
    res.sendStatus(200);
  } catch (err) {
    res.status(500).json({ error: "删除失败" });
  }
});
// 1. 注册
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const check = await pool.query("SELECT * FROM users WHERE username=$1", [
      username,
    ]);
    if (check.rows.length > 0)
      return res.status(400).json({ error: "用户名已存在" });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (username,password) VALUES ($1,$2) RETURNING id,username",
      [username, hash],
    );
    res.json({ message: "注册成功", user: result.rows[0] });
  } catch (e) {
    res.status(500).json({ error: "服务器错误" });
  }
});

// 2. 登录
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE username=$1", [
      username,
    ]);
    if (result.rows.length === 0)
      return res.status(400).json({ error: "用户名或密码错误" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "用户名或密码错误" });

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );
    res.json({
      message: "登录成功",
      token,
      user: { id: user.id, username: user.username },
    });
  } catch (e) {
    res.status(500).json({ error: "服务器错误" });
  }
});

// 3. 同步数据到云端
app.post("/api/sync", authenticateToken, async (req, res) => {
  try {
    const { recordId, target, captures, quickButtons } = req.body;
    const userId = req.user.id;

    console.log("同步数据 =>", { userId, recordId, target });

    const exists = await pool.query(
      "SELECT * FROM locke_records WHERE user_id=$1 AND record_id=$2",
      [userId, recordId],
    );

    if (exists.rows.length > 0) {
      await pool.query(
        "UPDATE locke_records SET target=$1, captures=$2, quick_buttons=$3, last_modified=NOW() WHERE user_id=$4 AND record_id=$5",
        [
          target,
          JSON.stringify(captures),
          JSON.stringify(quickButtons || []),
          userId,
          recordId,
        ],
      );
      return res.json({ message: "更新成功" });
    }

    await pool.query(
      "INSERT INTO locke_records (user_id, record_id, target, captures, quick_buttons) VALUES ($1,$2,$3,$4,$5)",
      [
        userId,
        recordId,
        target,
        JSON.stringify(captures),
        JSON.stringify(quickButtons || []),
      ],
    );
    res.json({ message: "同步成功" });
  } catch (e) {
    console.log("错误详情：", e);
    res.status(500).json({ error: "同步失败" });
  }
});

// 4. 从云端拉取数据
app.get("/api/pull", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      "SELECT record_id, target, captures, quick_buttons, created_at, last_modified FROM locke_records WHERE user_id=$1",
      [userId],
    );
    res.json({ records: result.rows });
  } catch (e) {
    res.status(500).json({ error: "拉取失败" });
  }
});

// 启动服务
app.listen(PORT, () => {
  console.log("✅ 服务运行在 http://localhost:3001");
});

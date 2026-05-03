require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3001;

// 1. 解决 CORS 问题：放在最前面
app.use(
  cors({
    origin: true, // 允许所有来源，或者填你的前端域名如 "https://your-frontend.vercel.app"
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    preflightContinue: false,
  }),
);

app.use(express.json());

// 连接 Neon PostgreSQL
const pool = new Pool({
  connectionString: process.env.NEON_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// JWT 验证中间件
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  // 如果是 OPTIONS 预检请求，直接放行（由 cors 中间件处理）
  if (req.method === "OPTIONS") return next();

  if (!token) {
    console.log("Auth Fail: No token provided");
    return res.status(401).json({ error: "未登录" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log("Auth Fail: Token invalid or expired");
      return res.status(403).json({ error: "登录已过期" });
    }
    req.user = user;
    next();
  });
}

// --- 路由 ---

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
    console.error(e);
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
    console.error(e);
    res.status(500).json({ error: "服务器错误" });
  }
});

// 3. 获取所有狩猎记录 (统一使用新表 roco_hunt_records)
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
    console.error(err);
    res.status(500).json({ error: "拉取记录失败" });
  }
});

// 修改后的 POST /api/hunts
app.post("/api/hunts", authenticateToken, async (req, res) => {
  const hunt = req.body;
  try {
    // 使用 ON CONFLICT ( PostgreSQL 特有语法)
    // 注意：这要求你的 roco_hunt_records 表在 (user_id, record_id) 上有唯一约束或主键
    await pool.query(
      `INSERT INTO roco_hunt_records (user_id, record_id, target, captures, last_modified) 
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (user_id, record_id) 
       DO UPDATE SET captures = EXCLUDED.captures, target = EXCLUDED.target, last_modified = NOW()`,
      [req.user.id, hunt.id, hunt.petName, hunt],
    );
    res.sendStatus(201);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "同步失败" });
  }
});

// 5. 更新记录
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
    console.error(err);
    res.status(500).json({ error: "更新失败" });
  }
});

// 6. 删除记录
app.delete("/api/hunts/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(
      "DELETE FROM roco_hunt_records WHERE user_id = $1 AND record_id = $2",
      [req.user.id, id],
    );
    res.sendStatus(200);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "删除失败" });
  }
});

// 健康检查接口，方便调试
app.get("/api/health", (req, res) => res.json({ status: "ok" }));

// 本地启动 (如果是部署到 Vercel，它会寻找导出的 app 而不是 listen 运行)
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`✅ 服务运行在 http://localhost:${PORT}`);
  });
}

// 导出 app 供 Vercel 使用 (重要)
module.exports = app;

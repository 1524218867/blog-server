require('dotenv').config()
const express = require('express')
const mysql = require('mysql2/promise')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')
const multer = require('multer')
const path = require('path')
const fs = require('fs')

const app = express()
app.use(cors())
app.use(express.json())

// 确保 uploads 目录存在
const uploadDir = path.join(__dirname, 'uploads')
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir)
}

// 配置 Multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir)
  },
  filename: function (req, file, cb) {
    // 保留原始扩展名
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, uniqueSuffix + path.extname(file.originalname))
  }
})
const upload = multer({ storage: storage })

// 静态文件服务
app.use('/uploads', express.static(uploadDir))

// 托管 Web 前端 (dist 目录)
const distDir = path.join(__dirname, 'dist')
if (fs.existsSync(distDir)) {
  app.use(express.static(distDir))
  // 处理 SPA 路由 (所有非 API 请求返回 index.html)
  // 排除 API 路由和其他静态资源路由
  app.get(/^(?!\/(uploads|api|auth|admin|health|video-groups|videos|image-groups|images|audio-groups|audios|dashboard)).*$/, (req, res) => {
     res.sendFile(path.join(distDir, 'index.html'))
  })
}


const dbConfig = {
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
}

const pool =
  dbConfig.host && dbConfig.user && dbConfig.database
    ? mysql.createPool(dbConfig)
    : null

const jwtSecret = process.env.JWT_SECRET

const issueToken = (user) => {
  if (!jwtSecret) {
    return null
  }
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    jwtSecret,
    { expiresIn: '7d' }
  )
}

const requireAuth = (req, res, next) => {
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) {
    res.status(401).json({ ok: false, reason: 'unauthorized' })
    return
  }
  if (!jwtSecret) {
    res.status(500).json({ ok: false, reason: 'server_not_configured' })
    return
  }
  try {
    req.user = jwt.verify(token, jwtSecret)
    next()
  } catch (_error) {
    res.status(401).json({ ok: false, reason: 'invalid_token' })
  }
}

const requireRole = (role) => (req, res, next) => {
  if (!req.user || req.user.role !== role) {
    res.status(403).json({ ok: false, reason: 'forbidden' })
    return
  }
  next()
}

const ensureSchema = async () => {
  if (!pool) {
    return
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('admin','user') NOT NULL DEFAULT 'user',
      created_at DATETIME NOT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS articles (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      content TEXT,
      tag VARCHAR(50),
      status ENUM('已发布', '草稿') NOT NULL DEFAULT '草稿',
      publish_date DATE,
      cover VARCHAR(255),
      created_at DATETIME NOT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      author_id INT UNSIGNED
    )
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS image_groups (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(50) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS images (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      url VARCHAR(255) NOT NULL,
      filename VARCHAR(255) NOT NULL,
      group_id INT UNSIGNED,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (group_id) REFERENCES image_groups(id) ON DELETE SET NULL
    )
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS video_groups (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(50) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS videos (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      url VARCHAR(255) NOT NULL,
      filename VARCHAR(255) NOT NULL,
      group_id INT UNSIGNED,
      duration VARCHAR(20),
      cover VARCHAR(255),
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (group_id) REFERENCES video_groups(id) ON DELETE SET NULL
    )
  `)

  // --- 新增：音乐相关表 ---
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audio_groups (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(50) NOT NULL,
      cover VARCHAR(255),
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)
  
  // 尝试添加 cover 列（如果表已存在但没有该列）
  try {
    await pool.query('ALTER TABLE audio_groups ADD COLUMN cover VARCHAR(255)')
  } catch (_e) {
    // 忽略重复列错误
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audios (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      url VARCHAR(255) NOT NULL,
      filename VARCHAR(255) NOT NULL,
      group_id INT UNSIGNED,
      duration VARCHAR(20),
      cover VARCHAR(255),
      singer VARCHAR(100),
      lyrics TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (group_id) REFERENCES audio_groups(id) ON DELETE SET NULL
    )
  `)

  // 尝试添加 lyrics 列（如果表已存在但没有该列）
  try {
    await pool.query('ALTER TABLE audios ADD COLUMN lyrics TEXT')
  } catch (_e) {
    // 忽略重复列错误
  }
  // -----------------------

  const adminEmail = process.env.ADMIN_EMAIL
  const adminPassword = process.env.ADMIN_PASSWORD
  if (!adminEmail || !adminPassword) {
    return
  }
  const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [
    adminEmail
  ])
  if (rows.length > 0) {
    return
  }
  const passwordHash = await bcrypt.hash(adminPassword, 10)
  await pool.query(
    'INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, NOW())',
    [adminEmail, passwordHash, 'admin']
  )
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true })
})

app.get('/api/health/db', async (_req, res) => {
  if (!pool) {
    res.status(503).json({ ok: false, reason: 'db_not_configured' })
    return
  }
  try {
    await ensureSchema()
    await pool.query('SELECT 1')
    res.json({ ok: true })
  } catch (_error) {
    res.status(503).json({ ok: false, reason: 'db_unavailable' })
  }
})

app.post('/api/auth/register', async (req, res) => {
  if (!pool) {
    res.status(503).json({ ok: false, reason: 'db_not_configured' })
    return
  }
  const { email, password } = req.body || {}
  if (
    typeof email !== 'string' ||
    typeof password !== 'string' ||
    email.length > 255 ||
    password.length < 8
  ) {
    res.status(400).json({ ok: false, reason: 'invalid_payload' })
    return
  }
  try {
    await ensureSchema()
    const [existing] = await pool.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    )
    if (existing.length > 0) {
      res.status(409).json({ ok: false, reason: 'email_exists' })
      return
    }
    const passwordHash = await bcrypt.hash(password, 10)
    const [result] = await pool.query(
      'INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, NOW())',
      [email, passwordHash, 'user']
    )
    res.json({
      ok: true,
      user: { id: result.insertId, email, role: 'user' }
    })
  } catch (_error) {
    res.status(500).json({ ok: false, reason: 'server_error' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  if (!pool) {
    res.status(503).json({ ok: false, reason: 'db_not_configured' })
    return
  }
  const { email, password } = req.body || {}
  if (typeof email !== 'string' || typeof password !== 'string') {
    res.status(400).json({ ok: false, reason: 'invalid_payload' })
    return
  }
  try {
    await ensureSchema()
    const [rows] = await pool.query(
      'SELECT id, email, password_hash, role FROM users WHERE email = ?',
      [email]
    )
    if (rows.length === 0) {
      res.status(401).json({ ok: false, reason: 'invalid_credentials' })
      return
    }
    const user = rows[0]
    const ok = await bcrypt.compare(password, user.password_hash)
    if (!ok) {
      res.status(401).json({ ok: false, reason: 'invalid_credentials' })
      return
    }
    const token = issueToken(user)
    if (!token) {
      res.status(500).json({ ok: false, reason: 'server_not_configured' })
      return
    }
    res.json({
      ok: true,
      token,
      user: { id: user.id, email: user.email, role: user.role }
    })
  } catch (_error) {
    res.status(500).json({ ok: false, reason: 'server_error' })
  }
})

app.get('/api/auth/me', requireAuth, async (req, res) => {
  res.json({ ok: true, user: req.user })
})

app.get('/api/admin/ping', requireAuth, requireRole('admin'), (_req, res) => {
  res.json({ ok: true })
})

// --- 文件上传 ---
app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) {
    res.status(400).json({ ok: false, reason: 'no_file' })
    return
  }
  
  // 修复中文文件名乱码
  req.file.originalname = Buffer.from(req.file.originalname, 'latin1').toString('utf8')

  // 返回完整 URL
  const protocol = req.protocol
  const host = req.get('host')
  const url = `${protocol}://${host}/uploads/${req.file.filename}`
  res.json({ ok: true, url })
})

// --- 文章管理 ---

// 获取列表
app.get('/api/articles', requireAuth, async (req, res) => {
  if (!pool) {
    res.status(503).json({ ok: false, reason: 'db_not_configured' })
    return
  }
  try {
    const { q } = req.query
    let sql = 'SELECT * FROM articles'
    const params = []
    
    if (q) {
      sql += ' WHERE title LIKE ? OR content LIKE ?'
      params.push(`%${q}%`, `%${q}%`)
    }
    
    sql += ' ORDER BY created_at DESC'
    const [rows] = await pool.query(sql, params)
    // 格式化日期以匹配前端需求 (YYYY-MM-DD)
    const list = rows.map(row => {
      // 优先使用 publish_date，否则用 created_at
      const d = row.publish_date || row.created_at
      // 处理日期对象
      let dateStr = ''
      if (d instanceof Date) {
        dateStr = d.toISOString().split('T')[0]
      } else if (typeof d === 'string') {
        dateStr = d.split('T')[0]
      }
      
      return {
        ...row,
        date: dateStr
      }
    })
    res.json(list)
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 获取详情
app.get('/api/articles/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    const [rows] = await pool.query('SELECT * FROM articles WHERE id = ?', [req.params.id])
    if (rows.length === 0) {
      res.status(404).json({ ok: false, reason: 'not_found' })
      return
    }
    const row = rows[0]
    const d = row.publish_date || row.created_at
    let dateStr = ''
    if (d instanceof Date) dateStr = d.toISOString().split('T')[0]
    else if (typeof d === 'string') dateStr = d.split('T')[0]
    
    res.json({ ...row, date: dateStr })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 创建文章
app.post('/api/articles', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { title, content, tag, status, date, cover } = req.body
  try {
    const [result] = await pool.query(
      'INSERT INTO articles (title, content, tag, status, publish_date, cover, author_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())',
      [title, content, tag, status, date, cover, req.user.id]
    )
    res.json({ ok: true, id: result.insertId })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 更新文章
app.put('/api/articles/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  const { title, content, tag, status, date, cover } = req.body
  try {
    await pool.query(
      'UPDATE articles SET title=?, content=?, tag=?, status=?, publish_date=?, cover=? WHERE id=?',
      [title, content, tag, status, date, cover, id]
    )
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 删除文章
app.delete('/api/articles/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  try {
    await pool.query('DELETE FROM articles WHERE id = ?', [id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// --- 图片与分组管理 ---

// 获取所有分组（带图片数量）
app.get('/api/image-groups', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    const [rows] = await pool.query(`
      SELECT g.*, COUNT(i.id) as image_count 
      FROM image_groups g 
      LEFT JOIN images i ON g.id = i.group_id 
      GROUP BY g.id 
      ORDER BY g.created_at ASC
    `)
    res.json(rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 创建分组
app.post('/api/image-groups', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { name } = req.body
  if (!name) return res.status(400).json({ ok: false, reason: 'missing_name' })
  try {
    const [result] = await pool.query('INSERT INTO image_groups (name) VALUES (?)', [name])
    res.json({ ok: true, id: result.insertId, name })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 删除分组
app.delete('/api/image-groups/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  try {
    // 由于设置了 ON DELETE SET NULL，删除分组后，其中的图片 group_id 会自动变为 NULL
    await pool.query('DELETE FROM image_groups WHERE id = ?', [id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 获取图片列表
app.get('/api/images', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { group_id, q } = req.query
  try {
    let sql = 'SELECT * FROM images'
    const params = []
    const conditions = []

    if (group_id !== undefined && group_id !== '') {
      if (group_id === 'null' || group_id === '0') {
        conditions.push('group_id IS NULL')
      } else {
        conditions.push('group_id = ?')
        params.push(group_id)
      }
    }

    if (q) {
      conditions.push('filename LIKE ?')
      params.push(`%${q}%`)
    }

    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ')
    }

    sql += ' ORDER BY created_at DESC'
    const [rows] = await pool.query(sql, params)
    res.json(rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 删除图片
app.delete('/api/images/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  try {
    // 先查询图片路径以便删除文件
    const [rows] = await pool.query('SELECT url FROM images WHERE id = ?', [id])
    if (rows.length > 0) {
      const url = rows[0].url
      // 从 URL 中提取物理文件名
      const filename = url.split('/').pop()
      const filePath = path.join(uploadDir, filename)
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath)
      }
    }
    await pool.query('DELETE FROM images WHERE id = ?', [id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 多图上传接口
app.post('/api/upload/multiple', requireAuth, upload.array('files'), async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ ok: false, reason: 'no_files' })
  }
  
  const groupId = req.body.group_id ? parseInt(req.body.group_id) : null
  const protocol = req.protocol
  const host = req.get('host')
  
  const results = []
  
  try {
    for (const file of req.files) {
      // 修复中文文件名乱码
      file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8')

      const url = `${protocol}://${host}/uploads/${file.filename}`
      // 使用原始文件名作为显示名
      const displayFilename = file.originalname
      
      const [result] = await pool.query(
        'INSERT INTO images (url, filename, group_id) VALUES (?, ?, ?)',
        [url, displayFilename, groupId]
      )
      results.push({
        id: result.insertId,
        url,
        filename: displayFilename,
        group_id: groupId
      })
    }
    res.json({ ok: true, files: results })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// --- 视频与分组管理 ---

// 获取所有视频分组（带视频数量）
app.get('/api/video-groups', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    const [rows] = await pool.query(`
      SELECT g.*, COUNT(v.id) as video_count 
      FROM video_groups g 
      LEFT JOIN videos v ON g.id = v.group_id 
      GROUP BY g.id 
      ORDER BY g.created_at ASC
    `)
    res.json(rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 创建视频分组
app.post('/api/video-groups', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { name } = req.body
  if (!name) return res.status(400).json({ ok: false, reason: 'missing_name' })
  try {
    const [result] = await pool.query('INSERT INTO video_groups (name) VALUES (?)', [name])
    res.json({ ok: true, id: result.insertId, name })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 删除视频分组
app.delete('/api/video-groups/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  try {
    await pool.query('DELETE FROM video_groups WHERE id = ?', [id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 获取视频列表
app.get('/api/videos', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { group_id, q } = req.query
  try {
    let sql = 'SELECT * FROM videos'
    const params = []
    const conditions = []

    if (group_id !== undefined && group_id !== '') {
      if (group_id === 'null' || group_id === '0') {
        conditions.push('group_id IS NULL')
      } else {
        conditions.push('group_id = ?')
        params.push(group_id)
      }
    }

    if (q) {
      conditions.push('filename LIKE ?')
      params.push(`%${q}%`)
    }

    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ')
    }

    sql += ' ORDER BY created_at DESC'
    const [rows] = await pool.query(sql, params)
    res.json(rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 删除视频
app.delete('/api/videos/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  try {
    const [rows] = await pool.query('SELECT url FROM videos WHERE id = ?', [id])
    if (rows.length > 0) {
      const url = rows[0].url
      const filename = url.split('/').pop()
      const filePath = path.join(uploadDir, filename)
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath)
      }
    }
    await pool.query('DELETE FROM videos WHERE id = ?', [id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 视频上传接口
app.post('/api/upload/videos', requireAuth, upload.array('files'), async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ ok: false, reason: 'no_files' })
  }
  
  const groupId = req.body.group_id ? parseInt(req.body.group_id) : null
  const protocol = req.protocol
  const host = req.get('host')
  
  const results = []
  
  try {
    for (const file of req.files) {
      // 修复中文文件名乱码
      file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8')
      
      const url = `${protocol}://${host}/uploads/${file.filename}`
      // 使用原始文件名作为显示名
      const displayFilename = file.originalname

      const [result] = await pool.query(
        'INSERT INTO videos (url, filename, group_id) VALUES (?, ?, ?)',
        [url, displayFilename, groupId]
      )
      results.push({
        id: result.insertId,
        url,
        filename: displayFilename,
        group_id: groupId
      })
    }
    res.json({ ok: true, files: results })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// --- 音乐与分组管理 ---

// 获取所有音乐分组（带音乐数量）
app.get('/api/audio-groups', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    // 修复 LEFT JOIN 计数问题：
    // 如果一个分组有多首歌，LEFT JOIN 会产生多行，GROUP BY g.id 会聚合这些行。
    // COUNT(a.id) 会统计非 NULL 的 a.id 数量，这是正确的。
    // 但是如果之前的 SQL 有问题，可能是因为数据问题或者其他。
    // 让我们确保 SQL 是标准的。
    const [rows] = await pool.query(`
      SELECT g.*, COUNT(a.id) as audio_count 
      FROM audio_groups g 
      LEFT JOIN audios a ON g.id = a.group_id 
      GROUP BY g.id 
      ORDER BY g.created_at ASC
    `)
    
    // 如果前端使用 item.audios.length，那么我们需要把 audios 也返回去？
    // 或者前端只用 audio_count？
    // 前端之前改成了 item.audios ? item.audios.length : 0
    // 这意味着前端期望返回 audios 数组。
    // 但当前的 SQL 并没有返回 audios 数组，只返回了 audio_count。
    // 所以我们需要修改 SQL 来返回 audios 列表，或者前端改回使用 audio_count。
    // 既然用户说“统计的不正确”，可能是前端取不到 audios 数组导致 length 为 0（如果 audios undefined）。
    
    // 方案 A：在后端聚合 audios (比较复杂，MySQL GROUP_CONCAT 长度有限制)
    // 方案 B：先查分组，再查所有 audios 组装（数据量大时慢）
    // 方案 C：前端改回使用 audio_count，并确保后端返回正确的 audio_count。
    
    // 现在的 SQL 确实返回了 audio_count。
    // 让我们检查前端代码。前端现在是 count: item.audios ? item.audios.length : 0
    // 因为 /audio-groups 接口目前只返回 { id, name, created_at, audio_count }
    // 所以 item.audios 是 undefined，导致 count 显示为 0。
    
    // 所以我们应该让前端使用 audio_count。
    // 但用户说“有分组的统计的不正确”，可能就是因为显示为 0。
    // 让我们恢复前端使用 audioCount，或者修改后端返回 audios（不推荐，数据量大）。
    // 最好是前端用 audio_count。
    
    // 等等，用户之前说“歌曲数量统计的不对”，那是因为之前前端用的 item.audioCount || 0，
    // 而后端返回的字段名是 audio_count (下划线)，不是 camelCase。
    // 所以前端应该用 item.audio_count。
    
    // 让我们修改后端返回 camelCase 的字段，或者前端适配。
    // 为了方便，我们在后端转换一下。
    
    const result = rows.map(row => ({
      ...row,
      audioCount: row.audio_count
    }))
    
    res.json(result)
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 创建音乐分组
app.post('/api/audio-groups', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { name, cover } = req.body
  if (!name) return res.status(400).json({ ok: false, reason: 'missing_name' })
  try {
    const [result] = await pool.query('INSERT INTO audio_groups (name, cover) VALUES (?, ?)', [name, cover])
    res.json({ ok: true, id: result.insertId, name, cover })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 更新音乐分组
app.put('/api/audio-groups/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  const { name, cover } = req.body
  try {
    await pool.query('UPDATE audio_groups SET name = ?, cover = ? WHERE id = ?', [name, cover, id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 删除音乐分组
app.delete('/api/audio-groups/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  try {
    await pool.query('DELETE FROM audio_groups WHERE id = ?', [id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 获取音乐列表
app.get('/api/audios', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { group_id, q } = req.query
  try {
    let sql = 'SELECT * FROM audios'
    const params = []
    const conditions = []

    if (group_id !== undefined && group_id !== '') {
      if (group_id === 'null' || group_id === '0') {
        conditions.push('group_id IS NULL')
      } else {
        conditions.push('group_id = ?')
        params.push(group_id)
      }
    }

    if (q) {
      conditions.push('(filename LIKE ? OR singer LIKE ?)')
      params.push(`%${q}%`, `%${q}%`)
    }

    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ')
    }

    sql += ' ORDER BY created_at DESC'
    const [rows] = await pool.query(sql, params)
    res.json(rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 更新音乐信息
app.put('/api/audios/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  const { filename, singer, lyrics, cover } = req.body
  try {
    await pool.query(
      'UPDATE audios SET filename=?, singer=?, lyrics=?, cover=? WHERE id=?',
      [filename, singer, lyrics, cover, id]
    )
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 删除音乐
app.delete('/api/audios/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  try {
    const [rows] = await pool.query('SELECT url FROM audios WHERE id = ?', [id])
    if (rows.length > 0) {
      const url = rows[0].url
      const filename = url.split('/').pop()
      const filePath = path.join(uploadDir, filename)
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath)
      }
    }
    await pool.query('DELETE FROM audios WHERE id = ?', [id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 音乐上传接口
app.post('/api/upload/audios', requireAuth, upload.array('files'), async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ ok: false, reason: 'no_files' })
  }
  
  const groupId = req.body.group_id ? parseInt(req.body.group_id) : null
  const protocol = req.protocol
  const host = req.get('host')
  
  const results = []
  
  try {
    // 1. 分离音频文件、LRC文件和图片文件
    const audioFiles = []
    const lrcFilesMap = new Map() // basename -> content
    const coverFilesMap = new Map() // basename -> filename (stored file name)

    for (const file of req.files) {
      // 修复中文文件名乱码
      file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8')
      
      const ext = path.extname(file.originalname).toLowerCase()
      const basename = path.parse(file.originalname).name
      
      if (ext === '.lrc') {
        // 读取LRC内容
        const content = fs.readFileSync(file.path, 'utf-8')
        lrcFilesMap.set(basename, content)
        // 读取后删除LRC文件，因为我们存入数据库了
        try {
          fs.unlinkSync(file.path)
        } catch (e) {
          console.error('Failed to delete lrc file:', e)
        }
      } else if (['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext)) {
        // 图片文件作为封面
        coverFilesMap.set(basename, file.filename)
      } else {
        // 假设其他都是音频文件
        audioFiles.push(file)
      }
    }

    // 2. 处理音频文件并关联歌词和封面
    for (const file of audioFiles) {
      const url = `${protocol}://${host}/uploads/${file.filename}`
      // 使用原始文件名（去掉后缀）作为显示名
      const displayFilename = path.parse(file.originalname).name
      
      // 查找匹配的歌词
      const lyrics = lrcFilesMap.get(displayFilename) || null
      
      // 查找匹配的封面
      let cover = null
      const coverFilename = coverFilesMap.get(displayFilename)
      if (coverFilename) {
        cover = `${protocol}://${host}/uploads/${coverFilename}`
      }

      const [result] = await pool.query(
        'INSERT INTO audios (url, filename, group_id, lyrics, cover) VALUES (?, ?, ?, ?, ?)',
        [url, displayFilename, groupId, lyrics, cover]
      )
      results.push({
        id: result.insertId,
        url,
        filename: displayFilename,
        group_id: groupId,
        lyrics: !!lyrics,
        cover
      })
    }
    
    // 如果有一些图片没有被匹配到音频，它们目前会保留在 uploads 目录中，但没有记录在 audios 表里。
    // 这对于相册功能是正常的，但这里是音频上传接口。
    // 暂时保留这些孤儿图片，或者我们可以选择删除它们。
    // 考虑到用户可能不小心传错名，保留着比较安全，或者后续可以清理。
    
    res.json({ ok: true, files: results })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// --- 仪表盘数据 ---
app.get('/api/dashboard/stats', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    // 1. 获取统计数据
    const [articleCount] = await pool.query('SELECT COUNT(*) as count FROM articles')
    const [imageCount] = await pool.query('SELECT COUNT(*) as count FROM images')
    const [videoCount] = await pool.query('SELECT COUNT(*) as count FROM videos')
    const [audioCount] = await pool.query('SELECT COUNT(*) as count FROM audios')

    // 2. 获取最近动态 (合并各表最新的记录)
    const [recentArticles] = await pool.query('SELECT id, title, created_at FROM articles ORDER BY created_at DESC LIMIT 3')
    const [recentImages] = await pool.query('SELECT id, filename, created_at FROM images ORDER BY created_at DESC LIMIT 3')
    const [recentVideos] = await pool.query('SELECT id, filename, created_at FROM videos ORDER BY created_at DESC LIMIT 3')
    const [recentAudios] = await pool.query('SELECT id, filename, created_at FROM audios ORDER BY created_at DESC LIMIT 3')

    let activities = []

    recentArticles.forEach(item => {
      activities.push({
        type: 'article',
        id: item.id,
        text: `发布了新文章《${item.title}》`,
        time: item.created_at
      })
    })

    recentImages.forEach(item => {
      activities.push({
        type: 'image',
        id: item.id,
        text: `上传了图片 ${item.filename}`,
        time: item.created_at
      })
    })

    recentVideos.forEach(item => {
      activities.push({
        type: 'video',
        id: item.id,
        text: `上传了视频 ${item.filename}`,
        time: item.created_at
      })
    })

    recentAudios.forEach(item => {
      activities.push({
        type: 'audio',
        id: item.id,
        text: `上传了音乐 ${item.filename}`,
        time: item.created_at
      })
    })

    // 按时间倒序排序
    activities.sort((a, b) => new Date(b.time) - new Date(a.time))
    // 取前 5 条
    activities = activities.slice(0, 5)

    res.json({
      ok: true,
      stats: {
        articles: articleCount[0].count,
        images: imageCount[0].count,
        videos: videoCount[0].count,
        audios: audioCount[0].count
      },
      recentActivities: activities
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// --- 全局搜索 ---
app.get('/api/search', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { q } = req.query
  if (!q) {
    return res.json({ ok: true, articles: [], images: [], videos: [], audios: [] })
  }

  try {
    const likeQ = `%${q}%`
    
    // 并行查询四个表
    const [articles] = await pool.query(
      'SELECT * FROM articles WHERE title LIKE ? OR content LIKE ? ORDER BY created_at DESC',
      [likeQ, likeQ]
    )
    
    const [images] = await pool.query(
      'SELECT * FROM images WHERE filename LIKE ? ORDER BY created_at DESC',
      [likeQ]
    )
    
    const [videos] = await pool.query(
      'SELECT * FROM videos WHERE filename LIKE ? ORDER BY created_at DESC',
      [likeQ]
    )
    
    const [audios] = await pool.query(
      'SELECT * FROM audios WHERE filename LIKE ? OR singer LIKE ? ORDER BY created_at DESC',
      [likeQ, likeQ]
    )
    
    // 格式化文章日期
    const formattedArticles = articles.map(row => {
      const d = row.publish_date || row.created_at
      let dateStr = ''
      if (d instanceof Date) {
        dateStr = d.toISOString().split('T')[0]
      } else if (typeof d === 'string') {
        dateStr = d.split('T')[0]
      }
      return { ...row, date: dateStr }
    })

    res.json({
      ok: true,
      articles: formattedArticles,
      images,
      videos,
      audios
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

const port = Number(process.env.PORT) || 3000
// 启动时尝试初始化数据库结构
ensureSchema().catch(err => {
  console.error('Failed to initialize DB schema:', err)
})

app.listen(port, () => {
  console.log(`blog-server listening on http://localhost:${port}`)
})

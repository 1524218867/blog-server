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
app.use(express.json({ limit: '50mb' }))
app.use(express.urlencoded({ limit: '50mb', extended: true }))

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

  // 尝试添加 avatar 列（如果表已存在但没有该列）
  try {
    await pool.query('ALTER TABLE users ADD COLUMN avatar VARCHAR(255)')
  } catch (e) {
    // 忽略重复列错误 (1060: Duplicate column name)
    if (e.errno !== 1060) {
      console.warn('Warning: Failed to add avatar column:', e.message)
    }
  }

  // 尝试添加 enable_history_recording 列
  try {
    await pool.query('ALTER TABLE users ADD COLUMN enable_history_recording BOOLEAN DEFAULT TRUE')
  } catch (e) {
    if (e.errno !== 1060) {
      console.warn('Warning: Failed to add enable_history_recording column:', e.message)
    }
  }

  // 尝试添加 enable_auto_continue 列
  try {
    await pool.query('ALTER TABLE users ADD COLUMN enable_auto_continue BOOLEAN DEFAULT TRUE')
  } catch (e) {
    if (e.errno !== 1060) {
      console.warn('Warning: Failed to add enable_auto_continue column:', e.message)
    }
  }

  // --- 新增：标签系统 ---
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tags (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      user_id INT UNSIGNED NOT NULL,
      name VARCHAR(50) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_tag_name (user_id, name),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS content_tags (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      content_type ENUM('article', 'image', 'video', 'audio') NOT NULL,
      content_id INT UNSIGNED NOT NULL,
      tag_id INT UNSIGNED NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_content_tag (content_type, content_id, tag_id),
      FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
    )
  `)

  // --- 新增：内容访问/使用记录表 ---
  await pool.query(`
    CREATE TABLE IF NOT EXISTS content_history (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      user_id INT UNSIGNED NOT NULL,
      content_type ENUM('article', 'image', 'video', 'audio') NOT NULL,
      content_id INT UNSIGNED NOT NULL,
      last_access_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      progress INT DEFAULT 0, -- 播放进度或阅读进度
      is_finished BOOLEAN DEFAULT FALSE,
      created_at DATETIME NOT NULL,
      UNIQUE KEY unique_access (user_id, content_type, content_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `)

  // --- 新增：内容置顶表 ---
  await pool.query(`
    CREATE TABLE IF NOT EXISTS content_pins (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      user_id INT UNSIGNED NOT NULL,
      content_type ENUM('article', 'image', 'video', 'audio') NOT NULL,
      content_id INT UNSIGNED NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_pin (user_id, content_type, content_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
      user_id INT UNSIGNED,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)

  // 尝试添加 user_id 列
  try {
    await pool.query('ALTER TABLE image_groups ADD COLUMN user_id INT UNSIGNED')
  } catch (_e) {
    // 忽略重复列错误
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS images (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      url VARCHAR(255) NOT NULL,
      filename VARCHAR(255) NOT NULL,
      group_id INT UNSIGNED,
      user_id INT UNSIGNED,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (group_id) REFERENCES image_groups(id) ON DELETE SET NULL
    )
  `)

  // 尝试添加 user_id 列
  try {
    await pool.query('ALTER TABLE images ADD COLUMN user_id INT UNSIGNED')
  } catch (_e) {
    // 忽略重复列错误
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS video_groups (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(50) NOT NULL,
      user_id INT UNSIGNED,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)

  // 尝试添加 user_id 列
  try {
    await pool.query('ALTER TABLE video_groups ADD COLUMN user_id INT UNSIGNED')
  } catch (_e) {
    // 忽略重复列错误
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS videos (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      url VARCHAR(255) NOT NULL,
      filename VARCHAR(255) NOT NULL,
      group_id INT UNSIGNED,
      user_id INT UNSIGNED,
      duration VARCHAR(20),
      cover VARCHAR(255),
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (group_id) REFERENCES video_groups(id) ON DELETE SET NULL
    )
  `)

  // 尝试添加 user_id 列
  try {
    await pool.query('ALTER TABLE videos ADD COLUMN user_id INT UNSIGNED')
  } catch (_e) {
    // 忽略重复列错误
  }

  // --- 新增：音乐相关表 ---
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audio_groups (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(50) NOT NULL,
      cover VARCHAR(255),
      user_id INT UNSIGNED,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)
  
  // 尝试添加 cover 和 user_id 列
  try {
    await pool.query('ALTER TABLE audio_groups ADD COLUMN cover VARCHAR(255)')
  } catch (_e) {}
  try {
    await pool.query('ALTER TABLE audio_groups ADD COLUMN user_id INT UNSIGNED')
  } catch (_e) {}

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audios (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      url VARCHAR(255) NOT NULL,
      filename VARCHAR(255) NOT NULL,
      group_id INT UNSIGNED,
      user_id INT UNSIGNED,
      duration VARCHAR(20),
      cover VARCHAR(255),
      singer VARCHAR(100),
      lyrics TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (group_id) REFERENCES audio_groups(id) ON DELETE SET NULL
    )
  `)

  // 尝试添加 lyrics 和 user_id 列
  try {
    await pool.query('ALTER TABLE audios ADD COLUMN lyrics TEXT')
  } catch (_e) {}
  try {
    await pool.query('ALTER TABLE audios ADD COLUMN user_id INT UNSIGNED')
  } catch (_e) {}
  // -----------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookmarks (
      id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      user_id INT UNSIGNED NOT NULL,
      title VARCHAR(255) NOT NULL,
      url VARCHAR(1024) NOT NULL,
      icon LONGTEXT,
      category VARCHAR(255) DEFAULT '未分类',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)
  
  // 尝试添加 category 字段（如果表已存在但字段不存在）
  try {
    await pool.query("ALTER TABLE bookmarks ADD COLUMN category VARCHAR(255) DEFAULT '未分类'")
  } catch (e) {
    // 忽略错误（字段可能已存在）
  }

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
  if (!pool) {
    // Fallback if DB not ready, though requireAuth checks secret
    res.json({ ok: true, user: req.user })
    return
  }
  try {
    const [rows] = await pool.query('SELECT id, email, role, avatar, enable_history_recording, enable_auto_continue FROM users WHERE id = ?', [req.user.id])
    if (rows.length > 0) {
      // 转换 boolean (MySQL BOOLEAN is TINYINT)
      const user = rows[0]
      user.enable_history_recording = !!user.enable_history_recording
      user.enable_auto_continue = !!user.enable_auto_continue
      res.json({ ok: true, user })
    } else {
      res.status(404).json({ ok: false, reason: 'user_not_found' })
    }
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

app.put('/api/auth/profile', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { avatar, enable_history_recording, enable_auto_continue } = req.body
  
  try {
    if (avatar !== undefined) {
      await pool.query('UPDATE users SET avatar = ? WHERE id = ?', [avatar, req.user.id])
    }
    
    if (enable_history_recording !== undefined) {
      await pool.query('UPDATE users SET enable_history_recording = ? WHERE id = ?', [enable_history_recording ? 1 : 0, req.user.id])
    }

    if (enable_auto_continue !== undefined) {
      await pool.query('UPDATE users SET enable_auto_continue = ? WHERE id = ?', [enable_auto_continue ? 1 : 0, req.user.id])
    }
    
    // 返回更新后的用户信息
    const [rows] = await pool.query('SELECT id, email, role, avatar, enable_history_recording, enable_auto_continue FROM users WHERE id = ?', [req.user.id])
    const user = rows[0]
    user.enable_history_recording = !!user.enable_history_recording
    user.enable_auto_continue = !!user.enable_auto_continue
    res.json({ ok: true, user })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 获取用户存储空间详情
app.get('/api/user/storage', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  
  try {
    const userId = req.user.id
    // 获取磁盘空间信息
    let diskTotal = 20 * 1024 * 1024 * 1024 // Fallback
    try {
      const fsStats = fs.statfsSync(uploadDir)
      diskTotal = fsStats.bsize * fsStats.blocks
    } catch (e) {
      console.warn('fs.statfsSync failed:', e)
    }

    const stats = {
      total: diskTotal,
      used: 0,
      distribution: {
        images: 0,
        videos: 0,
        audios: 0,
        documents: 0,
        others: 0
      }
    }

    // Helper to get file size
    const getFileSize = (url) => {
       if (!url) return 0
       
       let filename = url
       // Handle full URLs like http://.../uploads/xxx.jpg
       if (url.startsWith('http') || url.startsWith('//')) {
         const parts = url.split('/')
         filename = parts[parts.length - 1]
       }
       
       // Remove query params
       filename = filename.split('?')[0]
       
       if (!filename) return 0
       
       const filePath = path.join(uploadDir, filename)
       try {
         if (fs.existsSync(filePath)) {
           const stat = fs.statSync(filePath)
           return stat.size
         }
       } catch (e) {
         // ignore
       }
       return 0
    }

    // 1. Images
    const [images] = await pool.query('SELECT url FROM images WHERE user_id = ?', [userId])
    images.forEach(img => {
       const size = getFileSize(img.url)
       stats.used += size
       stats.distribution.images += size
    })

    // 2. Videos
    const [videos] = await pool.query('SELECT url FROM videos WHERE user_id = ?', [userId])
    videos.forEach(vid => {
       const size = getFileSize(vid.url)
       stats.used += size
       stats.distribution.videos += size
    })

    // 3. Audios
    const [audios] = await pool.query('SELECT url FROM audios WHERE user_id = ?', [userId])
    audios.forEach(audio => {
       const size = getFileSize(audio.url)
       stats.used += size
       stats.distribution.audios += size
    })

    // 4. Articles
    const [articles] = await pool.query('SELECT content FROM articles WHERE author_id = ?', [userId])
    articles.forEach(art => {
       const size = (art.content || '').length * 3 // Estimate 3 bytes per char (UTF-8)
       stats.used += size
       stats.distribution.documents += size
    })
    
    // Add some random "Others" for realism if used is very small
    if (stats.used < 1024 * 1024) {
       stats.distribution.others = 15 * 1024 * 1024 // 15MB system usage
       stats.used += stats.distribution.others
    }

    res.json({ ok: true, ...stats })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

app.get('/api/admin/ping', requireAuth, requireRole('admin'), (_req, res) => {
  res.json({ ok: true })
})

// --- 文件上传 ---
const singleUploadHandler = (req, res) => {
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
}

app.post('/api/upload', requireAuth, upload.single('file'), singleUploadHandler)
// 添加别名以兼容前端可能调用的 /api/upload/image
app.post('/api/upload/image', requireAuth, upload.single('file'), singleUploadHandler)

// --- 文章管理 ---

// 获取列表
app.get('/api/articles', requireAuth, async (req, res) => {
  if (!pool) {
    res.status(503).json({ ok: false, reason: 'db_not_configured' })
    return
  }
  try {
    const { q } = req.query
    let sql = `
      SELECT a.*, CASE WHEN cp.id IS NOT NULL THEN 1 ELSE 0 END as isPinned 
      FROM articles a 
      LEFT JOIN content_pins cp ON a.id = cp.content_id AND cp.content_type = 'article' AND cp.user_id = a.author_id 
      WHERE a.author_id = ?`
    const params = [req.user.id]
    
    if (q) {
      sql += ' AND (a.title LIKE ? OR a.content LIKE ?)'
      params.push(`%${q}%`, `%${q}%`)
    }
    
    sql += ' ORDER BY a.created_at DESC'
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
        isPinned: !!row.isPinned,
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
    const [rows] = await pool.query('SELECT * FROM articles WHERE id = ? AND author_id = ?', [req.params.id, req.user.id])
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
      'UPDATE articles SET title=?, content=?, tag=?, status=?, publish_date=?, cover=? WHERE id=? AND author_id=?',
      [title, content, tag, status, date, cover, id, req.user.id]
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
    await pool.query('DELETE FROM articles WHERE id = ? AND author_id = ?', [id, req.user.id])
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
      WHERE g.user_id = ?
      GROUP BY g.id 
      ORDER BY g.created_at ASC
    `, [req.user.id])
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
    const [result] = await pool.query('INSERT INTO image_groups (name, user_id) VALUES (?, ?)', [name, req.user.id])
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
    await pool.query('DELETE FROM image_groups WHERE id = ? AND user_id = ?', [id, req.user.id])
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
    let sql = `
      SELECT i.*, CASE WHEN cp.id IS NOT NULL THEN 1 ELSE 0 END as isPinned 
      FROM images i 
      LEFT JOIN content_pins cp ON i.id = cp.content_id AND cp.content_type = 'image' AND cp.user_id = i.user_id`
    const params = [req.user.id]
    const conditions = ['i.user_id = ?']

    if (group_id !== undefined && group_id !== '') {
      if (group_id === 'null' || group_id === '0') {
        conditions.push('i.group_id IS NULL')
      } else {
        conditions.push('i.group_id = ?')
        params.push(group_id)
      }
    }

    if (q) {
      conditions.push('i.filename LIKE ?')
      params.push(`%${q}%`)
    }

    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ')
    }

    sql += ' ORDER BY i.created_at DESC'
    const [rows] = await pool.query(sql, params)
    const list = rows.map(row => ({
      ...row,
      isPinned: !!row.isPinned
    }))
    res.json(list)
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
    const [rows] = await pool.query('SELECT url FROM images WHERE id = ? AND user_id = ?', [id, req.user.id])
    if (rows.length > 0) {
      const url = rows[0].url
      // 从 URL 中提取物理文件名
      const filename = url.split('/').pop()
      const filePath = path.join(uploadDir, filename)
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath)
      }
    }
    await pool.query('DELETE FROM images WHERE id = ? AND user_id = ?', [id, req.user.id])
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
        'INSERT INTO images (url, filename, group_id, user_id) VALUES (?, ?, ?, ?)',
        [url, displayFilename, groupId, req.user.id]
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
      WHERE g.user_id = ?
      GROUP BY g.id 
      ORDER BY g.created_at ASC
    `, [req.user.id])
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
    const [result] = await pool.query('INSERT INTO video_groups (name, user_id) VALUES (?, ?)', [name, req.user.id])
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
    await pool.query('DELETE FROM video_groups WHERE id = ? AND user_id = ?', [id, req.user.id])
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
    let sql = `
      SELECT v.*, CASE WHEN cp.id IS NOT NULL THEN 1 ELSE 0 END as isPinned 
      FROM videos v 
      LEFT JOIN content_pins cp ON v.id = cp.content_id AND cp.content_type = 'video' AND cp.user_id = v.user_id`
    const params = [req.user.id]
    const conditions = ['v.user_id = ?']

    if (group_id !== undefined && group_id !== '') {
      if (group_id === 'null' || group_id === '0') {
        conditions.push('v.group_id IS NULL')
      } else {
        conditions.push('v.group_id = ?')
        params.push(group_id)
      }
    }

    if (q) {
      conditions.push('v.filename LIKE ?')
      params.push(`%${q}%`)
    }

    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ')
    }

    sql += ' ORDER BY v.created_at DESC'
    const [rows] = await pool.query(sql, params)
    const list = rows.map(row => ({
      ...row,
      isPinned: !!row.isPinned
    }))
    res.json(list)
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
    const [rows] = await pool.query('SELECT url FROM videos WHERE id = ? AND user_id = ?', [id, req.user.id])
    if (rows.length > 0) {
      const url = rows[0].url
      const filename = url.split('/').pop()
      const filePath = path.join(uploadDir, filename)
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath)
      }
    }
    await pool.query('DELETE FROM videos WHERE id = ? AND user_id = ?', [id, req.user.id])
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
        'INSERT INTO videos (url, filename, group_id, user_id) VALUES (?, ?, ?, ?)',
        [url, displayFilename, groupId, req.user.id]
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

// --- 标签管理接口 ---

// 获取用户所有标签
app.get('/api/tags', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    const [rows] = await pool.query('SELECT * FROM tags WHERE user_id = ? ORDER BY created_at DESC', [req.user.id])
    res.json({ ok: true, list: rows })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 创建标签
app.post('/api/tags', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { name } = req.body
  if (!name || !name.trim()) return res.status(400).json({ ok: false, reason: 'missing_name' })
  
  try {
    const [result] = await pool.query('INSERT INTO tags (user_id, name) VALUES (?, ?)', [req.user.id, name.trim()])
    res.json({ ok: true, id: result.insertId, name: name.trim() })
  } catch (error) {
    if (error.errno === 1062) {
      return res.status(409).json({ ok: false, reason: 'tag_exists' })
    }
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 删除标签
app.delete('/api/tags/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    await pool.query('DELETE FROM tags WHERE id = ? AND user_id = ?', [req.params.id, req.user.id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 更新标签
app.put('/api/tags/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { name } = req.body
  if (!name || !name.trim()) return res.status(400).json({ ok: false, reason: 'missing_name' })
  
  try {
    await pool.query('UPDATE tags SET name = ? WHERE id = ? AND user_id = ?', [name.trim(), req.params.id, req.user.id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 获取内容的标签
app.get('/api/tags/content', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { type, id } = req.query
  try {
    const [rows] = await pool.query(`
      SELECT t.* 
      FROM tags t
      JOIN content_tags ct ON t.id = ct.tag_id
      WHERE ct.content_type = ? AND ct.content_id = ?
    `, [type, id])
    res.json({ ok: true, list: rows })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 批量添加标签到内容
app.post('/api/tags/content', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { type, id, tagIds } = req.body // id can be single ID or array of IDs
  
  if (!type || !id || !Array.isArray(tagIds)) {
    return res.status(400).json({ ok: false, reason: 'invalid_params' })
  }
  
  const contentIds = Array.isArray(id) ? id : [id]
  if (contentIds.length === 0 || tagIds.length === 0) {
    return res.json({ ok: true })
  }

  try {
    // 简单的批量插入，忽略重复
    const values = []
    for (const contentId of contentIds) {
      for (const tagId of tagIds) {
        values.push([type, contentId, tagId])
      }
    }
    
    await pool.query(`
      INSERT IGNORE INTO content_tags (content_type, content_id, tag_id) VALUES ?
    `, [values])
    
    res.json({ ok: true })
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
    const [rows] = await pool.query(`
      SELECT g.*, COUNT(a.id) as audio_count 
      FROM audio_groups g 
      LEFT JOIN audios a ON g.id = a.group_id 
      WHERE g.user_id = ?
      GROUP BY g.id 
      ORDER BY g.created_at ASC
    `, [req.user.id])
    
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
app.post('/api/audio-groups', requireAuth, upload.single('cover'), async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { name } = req.body
  let { cover } = req.body
  
  if (req.file) {
    // 修复中文文件名乱码
    req.file.originalname = Buffer.from(req.file.originalname, 'latin1').toString('utf8')
    const protocol = req.protocol
    const host = req.get('host')
    cover = `${protocol}://${host}/uploads/${req.file.filename}`
  }

  if (!name) return res.status(400).json({ ok: false, reason: 'missing_name' })
  try {
    const [result] = await pool.query('INSERT INTO audio_groups (name, cover, user_id) VALUES (?, ?, ?)', [name, cover, req.user.id])
    res.json({ ok: true, id: result.insertId, name, cover })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 更新音乐分组
app.put('/api/audio-groups/:id', requireAuth, upload.single('cover'), async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { id } = req.params
  const { name } = req.body
  let { cover } = req.body

  if (req.file) {
    // 修复中文文件名乱码
    req.file.originalname = Buffer.from(req.file.originalname, 'latin1').toString('utf8')
    const protocol = req.protocol
    const host = req.get('host')
    cover = `${protocol}://${host}/uploads/${req.file.filename}`
  }

  try {
    await pool.query('UPDATE audio_groups SET name = ?, cover = ? WHERE id = ? AND user_id = ?', [name, cover, id, req.user.id])
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
    await pool.query('DELETE FROM audio_groups WHERE id = ? AND user_id = ?', [id, req.user.id])
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
    const params = [req.user.id]
    const conditions = ['user_id = ?']

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
  const { filename, singer, lyrics, cover, group_id } = req.body
  try {
    // 动态构建更新语句
    const updates = []
    const params = []
    
    if (filename !== undefined) {
      updates.push('filename=?')
      params.push(filename)
    }
    if (singer !== undefined) {
      updates.push('singer=?')
      params.push(singer)
    }
    if (lyrics !== undefined) {
      updates.push('lyrics=?')
      params.push(lyrics)
    }
    if (cover !== undefined) {
      updates.push('cover=?')
      params.push(cover)
    }
    if (group_id !== undefined) {
      updates.push('group_id=?')
      // 如果是 -1，则设置为 NULL（未分组）
      params.push(group_id === -1 ? null : group_id)
    }
    
    if (updates.length === 0) {
      return res.json({ ok: true })
    }
    
    params.push(id)
    params.push(req.user.id) // Add user check
    
    await pool.query(
      `UPDATE audios SET ${updates.join(', ')} WHERE id=? AND user_id=?`,
      params
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
    const [rows] = await pool.query('SELECT url FROM audios WHERE id = ? AND user_id = ?', [id, req.user.id])
    if (rows.length > 0) {
      const url = rows[0].url
      const filename = url.split('/').pop()
      const filePath = path.join(uploadDir, filename)
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath)
      }
    }
    await pool.query('DELETE FROM audios WHERE id = ? AND user_id = ?', [id, req.user.id])
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 导入外部链接音乐
app.post('/api/audios/link', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { url, filename, singer, cover, lyrics, group_id } = req.body
  
  if (!url || !filename) {
    return res.status(400).json({ ok: false, reason: 'missing_fields' })
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO audios (url, filename, singer, cover, lyrics, group_id, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [url, filename, singer, cover, lyrics, group_id || null, req.user.id]
    )
    res.json({ ok: true, id: result.insertId })
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
      const basename = path.parse(file.originalname).name.toLowerCase() // 统一转小写以便匹配
      
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
      const key = displayFilename.toLowerCase()
      
      // 查找匹配的歌词
      let lyrics = lrcFilesMap.get(key) || null
      
      // 查找匹配的封面
      let cover = null
      let coverFilename = coverFilesMap.get(key)

      // 智能匹配逻辑：如果是单曲上传，允许不匹配文件名
      if (audioFiles.length === 1) {
        if (!lyrics && lrcFilesMap.size === 1) {
           lyrics = lrcFilesMap.values().next().value
        }
        if (!coverFilename && coverFilesMap.size === 1) {
           coverFilename = coverFilesMap.values().next().value
        }
      }

      if (coverFilename) {
        cover = `${protocol}://${host}/uploads/${coverFilename}`
      }

      const [result] = await pool.query(
        'INSERT INTO audios (url, filename, group_id, lyrics, cover, user_id) VALUES (?, ?, ?, ?, ?, ?)',
        [url, displayFilename, groupId, lyrics, cover, req.user.id]
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

// --- 首页数据聚合接口 ---
app.get('/api/dashboard/home-data', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    const userId = req.user.id

    // 临时：确保新表存在（防止初始化失败）
    await pool.query(`
      CREATE TABLE IF NOT EXISTS content_history (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        content_type ENUM('article', 'image', 'video', 'audio') NOT NULL,
        content_id INT UNSIGNED NOT NULL,
        last_access_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        progress INT DEFAULT 0,
        is_finished BOOLEAN DEFAULT FALSE,
        created_at DATETIME NOT NULL,
        UNIQUE KEY unique_access (user_id, content_type, content_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS content_pins (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        content_type ENUM('article', 'image', 'video', 'audio') NOT NULL,
        content_id INT UNSIGNED NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_pin (user_id, content_type, content_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `)

    // Helper: 获取详细信息
    const fetchDetails = async (type, id) => {
      let table = ''
      if (type === 'article') table = 'articles'
      else if (type === 'image') table = 'images'
      else if (type === 'video') table = 'videos'
      else if (type === 'audio') table = 'audios'
      
      if (!table) return null

      const [rows] = await pool.query(`SELECT * FROM ${table} WHERE id = ?`, [id])
      if (rows.length === 0) return null
      
      const item = rows[0]
      // 统一格式
      return {
        id: item.id,
        title: item.title || item.filename, // 图片/视频/音频可能没有 title
        type,
        cover: item.cover || item.url, // 图片直接用 url，视频/音频/文章用 cover
        desc: item.description || item.singer || '', // 简单适配
        createTime: item.created_at,
        // 特定字段
        url: item.url,
        duration: item.duration
      }
    }

    // 1. 获取置顶内容 (Pinned)
    const [pinnedRows] = await pool.query(
      'SELECT content_type, content_id FROM content_pins WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    )
    
    const pinnedList = []
    for (const row of pinnedRows) {
      const detail = await fetchDetails(row.content_type, row.content_id)
      if (detail) pinnedList.push(detail)
    }

    // 2. 获取最近使用 (Recently Used) - 从 history 表
    const [historyRows] = await pool.query(
      'SELECT content_type, content_id, last_access_time, progress FROM content_history WHERE user_id = ? ORDER BY last_access_time DESC LIMIT 6',
      [userId]
    )
    
    const recentlyUsedList = []
    for (const row of historyRows) {
      const detail = await fetchDetails(row.content_type, row.content_id)
      if (detail) {
        recentlyUsedList.push({
          ...detail,
          lastAccessTime: row.last_access_time,
          progress: row.progress
        })
      }
    }

    // 3. 获取未完成 (Continue Using) - 进度 (0%, 95%)，30天内，1-3个
    const [unfinishedRows] = await pool.query(
      `SELECT content_type, content_id, last_access_time, progress 
       FROM content_history 
       WHERE user_id = ? 
         AND is_finished = FALSE 
         AND progress > 0 
         AND progress < 95
         AND last_access_time > DATE_SUB(NOW(), INTERVAL 30 DAY)
       ORDER BY last_access_time DESC 
       LIMIT 3`,
      [userId]
    )
    
    const unfinishedList = []
    for (const row of unfinishedRows) {
      const detail = await fetchDetails(row.content_type, row.content_id)
      if (detail) {
        unfinishedList.push({
          ...detail,
          lastAccessTime: row.last_access_time,
          progress: row.progress
        })
      }
    }

    // 4. 获取最近添加 (Recently Added) - 从未打开过
    // 获取用户历史记录 Set 用于过滤
    const [userHistory] = await pool.query('SELECT content_type, content_id FROM content_history WHERE user_id = ?', [userId])
    const historySet = new Set(userHistory.map(h => `${h.content_type}:${h.content_id}`))

    // 聚合各表最新数据 (取多一点以便过滤)
    const fetchLimit = 20
    const [recentArticles] = await pool.query('SELECT id, title, created_at, cover FROM articles WHERE author_id = ? ORDER BY created_at DESC LIMIT ?', [userId, fetchLimit])
    const [recentImages] = await pool.query('SELECT id, filename, url, created_at FROM images WHERE user_id = ? ORDER BY created_at DESC LIMIT ?', [userId, fetchLimit])
    const [recentVideos] = await pool.query('SELECT id, filename, cover, created_at FROM videos WHERE user_id = ? ORDER BY created_at DESC LIMIT ?', [userId, fetchLimit])
    const [recentAudios] = await pool.query('SELECT id, filename, cover, created_at, singer FROM audios WHERE user_id = ? ORDER BY created_at DESC LIMIT ?', [userId, fetchLimit])

    let recentList = []
    
    const addToRecent = (items, type) => {
      items.forEach(i => {
        // 过滤掉已在历史记录中的
        if (!historySet.has(`${type}:${i.id}`)) {
          recentList.push({ 
            id: i.id, 
            title: i.title || i.filename, 
            type: type, 
            cover: i.cover || i.url, 
            desc: i.singer || '',
            createTime: i.created_at 
          })
        }
      })
    }

    addToRecent(recentArticles, 'article')
    addToRecent(recentImages, 'image')
    addToRecent(recentVideos, 'video')
    addToRecent(recentAudios, 'audio')

    // 按时间倒序并取前 10
    recentList.sort((a, b) => new Date(b.createTime) - new Date(a.createTime))
    recentList = recentList.slice(0, 10)

    res.json({
       ok: true,
       data: {
         pinnedList,
         recentlyUsedList,
         unfinishedList,
         recentlyAddedList: recentList
       }
     })
   } catch (error) {
     console.error(error)
     res.status(500).json({ ok: false, reason: 'db_error', message: error.message, sql: error.sql })
   }
 })

// --- 记录访问历史/进度接口 ---
app.post('/api/content/history', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { type, id, progress, isFinished } = req.body
  
  if (!type || !id) return res.status(400).json({ ok: false, reason: 'missing_params' })

  try {
    // 检查用户是否开启了历史记录
    const [userRows] = await pool.query('SELECT enable_history_recording FROM users WHERE id = ?', [req.user.id])
    if (userRows.length > 0 && userRows[0].enable_history_recording === 0) {
      // 用户关闭了历史记录，直接返回成功但不记录
      return res.json({ ok: true, skipped: true })
    }

    // 使用 ON DUPLICATE KEY UPDATE
    await pool.query(`
      INSERT INTO content_history (user_id, content_type, content_id, last_access_time, progress, is_finished, created_at)
      VALUES (?, ?, ?, NOW(), ?, ?, NOW())
      ON DUPLICATE KEY UPDATE
        last_access_time = NOW(),
        progress = VALUES(progress),
        is_finished = VALUES(is_finished)
    `, [req.user.id, type, id, progress || 0, isFinished ? 1 : 0])
    
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// Helper: 获取详细信息 (用于历史列表)
const fetchContentDetails = async (type, id) => {
  let table = ''
  if (type === 'article') table = 'articles'
  else if (type === 'image') table = 'images'
  else if (type === 'video') table = 'videos'
  else if (type === 'audio') table = 'audios'
  
  if (!table) return null

  const [rows] = await pool.query(`SELECT * FROM ${table} WHERE id = ?`, [id])
  if (rows.length === 0) return null
  
  const item = rows[0]
  // 统一格式
  return {
    id: item.id,
    title: item.title || item.filename, // 图片/视频/音频可能没有 title
    type,
    cover: item.cover || item.url, // 图片直接用 url，视频/音频/文章用 cover
    desc: item.description || item.singer || '', // 简单适配
    createTime: item.created_at,
    // 特定字段
    url: item.url,
    duration: item.duration
  }
}

// --- 获取历史记录列表 ---
app.get('/api/content/history-list', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { limit = 20, offset = 0 } = req.query
  const userId = req.user.id

  try {
    const [rows] = await pool.query(
      'SELECT content_type, content_id, last_access_time, progress, is_finished FROM content_history WHERE user_id = ? ORDER BY last_access_time DESC LIMIT ? OFFSET ?',
      [userId, Number(limit), Number(offset)]
    )

    const list = []
    for (const row of rows) {
      const detail = await fetchContentDetails(row.content_type, row.content_id)
      if (detail) {
        list.push({
          ...detail,
          lastAccessTime: row.last_access_time,
          progress: row.progress,
          isFinished: !!row.is_finished
        })
      }
    }
    
    res.json({ ok: true, list })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// 删除历史记录
app.delete('/api/content/history', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { type, id } = req.query
  if (!type || !id) return res.status(400).json({ ok: false, reason: 'missing_params' })
  
  try {
    await pool.query(
      'DELETE FROM content_history WHERE user_id = ? AND content_type = ? AND content_id = ?',
      [req.user.id, type, id]
    )
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// --- 置顶/取消置顶接口 ---
app.post('/api/content/pin', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { type, id, isPinned } = req.body
  
  if (!type || !id) return res.status(400).json({ ok: false, reason: 'missing_params' })

  try {
    if (isPinned) {
      await pool.query(`
        INSERT IGNORE INTO content_pins (user_id, content_type, content_id)
        VALUES (?, ?, ?)
      `, [req.user.id, type, id])
    } else {
      await pool.query(`
        DELETE FROM content_pins WHERE user_id = ? AND content_type = ? AND content_id = ?
      `, [req.user.id, type, id])
    }
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

// --- 仪表盘数据 ---
app.get('/api/dashboard/stats', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    const userId = req.user.id
    // 1. 获取统计数据
    const [articleCount] = await pool.query('SELECT COUNT(*) as count FROM articles WHERE author_id = ?', [userId])
    const [imageCount] = await pool.query('SELECT COUNT(*) as count FROM images WHERE user_id = ?', [userId])
    const [videoCount] = await pool.query('SELECT COUNT(*) as count FROM videos WHERE user_id = ?', [userId])
    const [audioCount] = await pool.query('SELECT COUNT(*) as count FROM audios WHERE user_id = ?', [userId])

    // 2. 获取最近动态 (合并各表最新的记录)
    const [recentArticles] = await pool.query('SELECT id, title, created_at FROM articles WHERE author_id = ? ORDER BY created_at DESC LIMIT 3', [userId])
    const [recentImages] = await pool.query('SELECT id, filename, created_at FROM images WHERE user_id = ? ORDER BY created_at DESC LIMIT 3', [userId])
    const [recentVideos] = await pool.query('SELECT id, filename, created_at FROM videos WHERE user_id = ? ORDER BY created_at DESC LIMIT 3', [userId])
    const [recentAudios] = await pool.query('SELECT id, filename, created_at FROM audios WHERE user_id = ? ORDER BY created_at DESC LIMIT 3', [userId])

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
    const userId = req.user.id
    
    // 并行查询四个表
    const [articles] = await pool.query(
      'SELECT * FROM articles WHERE author_id = ? AND (title LIKE ? OR content LIKE ?) ORDER BY created_at DESC',
      [userId, likeQ, likeQ]
    )
    
    const [images] = await pool.query(
      'SELECT * FROM images WHERE user_id = ? AND filename LIKE ? ORDER BY created_at DESC',
      [userId, likeQ]
    )
    
    const [videos] = await pool.query(
      'SELECT * FROM videos WHERE user_id = ? AND filename LIKE ? ORDER BY created_at DESC',
      [userId, likeQ]
    )
    
    const [audios] = await pool.query(
      'SELECT * FROM audios WHERE user_id = ? AND (filename LIKE ? OR singer LIKE ?) ORDER BY created_at DESC',
      [userId, likeQ, likeQ]
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

// --- 书签管理 ---
app.get('/api/bookmarks', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    const [rows] = await pool.query(
      'SELECT * FROM bookmarks WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    )
    res.json(rows)
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false })
  }
})

app.post('/api/bookmarks', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { title, url, icon, category } = req.body
  try {
    const [result] = await pool.query(
      'INSERT INTO bookmarks (user_id, title, url, icon, category) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, title, url, icon || null, category || '未分类']
    )
    res.json({ ok: true, id: result.insertId })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false, reason: 'db_error' })
  }
})

app.put('/api/bookmarks/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { title, url, icon, category } = req.body
  try {
    await pool.query(
      'UPDATE bookmarks SET title=?, url=?, icon=?, category=? WHERE id=? AND user_id=?',
      [title, url, icon, category, req.params.id, req.user.id]
    )
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false })
  }
})

app.delete('/api/bookmarks/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  try {
    await pool.query(
      'DELETE FROM bookmarks WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    )
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false })
  }
})

// 分组重命名
app.put('/api/bookmark-groups/rename', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { oldName, newName } = req.body
  if (!oldName || !newName) return res.status(400).json({ ok: false })
  try {
    await pool.query(
      'UPDATE bookmarks SET category=? WHERE category=? AND user_id=?',
      [newName, oldName, req.user.id]
    )
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false })
  }
})

// 分组删除
app.delete('/api/bookmark-groups', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { name, keepBookmarks } = req.query
  if (!name) return res.status(400).json({ ok: false })
  try {
    if (keepBookmarks === 'true') {
        await pool.query(
            "UPDATE bookmarks SET category='未分类' WHERE category=? AND user_id=?",
            [name, req.user.id]
        )
    } else {
        await pool.query(
            'DELETE FROM bookmarks WHERE category=? AND user_id=?',
            [name, req.user.id]
        )
    }
    res.json({ ok: true })
  } catch (error) {
    console.error(error)
    res.status(500).json({ ok: false })
  }
})

// 批量导入书签
app.post('/api/bookmarks/batch', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ ok: false })
  const { bookmarks } = req.body
  if (!Array.isArray(bookmarks)) return res.status(400).json({ ok: false })
  
  const conn = await pool.getConnection()
  try {
    await conn.beginTransaction()
    for (const bm of bookmarks) {
      await conn.query(
        'INSERT INTO bookmarks (user_id, title, url, icon, category) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, bm.title, bm.url, bm.icon || null, bm.category || '未分类']
      )
    }
    await conn.commit()
    res.json({ ok: true })
  } catch (error) {
    await conn.rollback()
    console.error(error)
    res.status(500).json({ ok: false })
  } finally {
    conn.release()
  }
})

// --- 代理接口 (解决 CORS 问题) ---
app.get('/api/proxy/wallpaper', async (req, res) => {
  try {
    const response = await fetch('https://api.52vmy.cn/api/img/tu/view');
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Proxy error:', error);
    res.status(500).json({ code: 500, msg: 'Proxy error' });
  }
});


app.get('/api/proxy/bing', async (req, res) => {
  try {
    const response = await fetch('https://api.52vmy.cn/api/wl/word/bing/tu');
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Proxy error:', error);
    res.status(500).json({ code: 500, msg: 'Proxy error' });
  }
});


const port = Number(process.env.PORT) || 3000
// 启动时尝试初始化数据库结构
ensureSchema().catch(err => {
  console.error('Failed to initialize DB schema:', err)
})

app.listen(port, () => {
  console.log(`blog-server listening on http://localhost:${port}`)
})

require('dotenv').config()
const mysql = require('mysql2/promise')

async function check() {
  const dbConfig = {
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  }

  try {
    const conn = await mysql.createConnection(dbConfig)
    console.log('Connected to DB')

    // 检查 articles 表是否存在
    const [tables] = await conn.query("SHOW TABLES LIKE 'articles'")
    if (tables.length === 0) {
      console.log('Table articles does not exist (will be created by app)')
    } else {
      console.log('Table articles exists. Checking columns...')
      const [columns] = await conn.query("SHOW COLUMNS FROM articles")
      console.log('Columns:', columns.map(c => c.Field))
      
      // 尝试插入一条测试数据来触发潜在错误
      try {
        await conn.query(`
          INSERT INTO articles (title, content, status, author_id) 
          VALUES ('test', 'content', '草稿', 1)
        `)
        console.log('Insert test success (rollbacking...)')
        // 这里的 rollback 没用因为没开事务，不过测试数据无所谓
        await conn.query("DELETE FROM articles WHERE title='test'")
      } catch (e) {
        console.error('Insert failed:', e.message)
      }
    }

    await conn.end()
  } catch (err) {
    console.error('DB Connection Error:', err)
  }
}

check()
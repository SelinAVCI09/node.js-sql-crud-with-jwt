const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const PORT = 3001;

const SECRET_KEY = 'selin';

// MySQL bağlantısı
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'w3schools'
});

// MySQL'e bağlanma
connection.connect((err) => {
  if (err) {
      console.error('Error connecting to MySQL: ' + err.stack);
      return;
  }
  console.log('Connected to MySQL as id ' + connection.threadId);

  // Örnek kullanıcı ekleme
  const username = 'user12';
  const plainPassword = 'user12';

  // Şifreyi hashleme
  const hashedPassword = bcrypt.hashSync(plainPassword, 8);

  const sql = 'INSERT INTO Users (username, password) VALUES (?, ?)';
  connection.query(sql, [username, hashedPassword], (err, results) => {
      if (err) {
          console.error('Error inserting user: ' + err);
          return;
      }
      console.log('User inserted with ID: ' + results.insertId);
  });
});
// Body-parser middleware'i
app.use(bodyParser.json());

// Kullanıcı Doğrulama
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM Users WHERE username = ?';
    connection.query(sql, [username], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.length === 0) {
            res.status(401).send({ message: 'Geçersiz kullanıcı adı veya şifre.' });
            return;
        }
        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) {
            res.status(401).send({ message: 'Geçersiz kullanıcı adı veya şifre.' });
            return;
        }
        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
        res.status(200).send({ auth: true, token });
    });
});

// JWT Doğrulama Middleware'i
function verifyToken(req, res, next) {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(403).send({ message: 'Token bulunamadı.' });
    }
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(500).send({ message: 'Token doğrulanamadı.' });
        }
        req.userId = decoded.id;
        next();
    });
}

// CRUD İşlemleri
// Create (Yeni müşteri ekleme)
app.post('/customers', verifyToken, (req, res) => {
    const { name, address } = req.body;
    const sql = 'INSERT INTO Customers (CustomerName, Address) VALUES (?, ?)';
    connection.query(sql, [name, address], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(201).send({ id: results.insertId, name, address });
    });
});

// Read (Müşterilerin listesini getirme)
app.get('/customers', verifyToken, (req, res) => {
    const sql = 'SELECT * FROM Customers';
    connection.query(sql, (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(200).send(results);
    });
});

// Update (Bir müşterinin bilgilerini güncelleme)
app.put('/customers/:id', verifyToken, (req, res) => {
    const { id } = req.params;
    const { name, address } = req.body;
    const sql = 'UPDATE Customers SET CustomerName = ?, Address = ? WHERE CustomerID = ?';
    connection.query(sql, [name, address, id], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).send({ message: 'Müşteri bulunamadı.' });
            return;
        }
        res.status(200).send({ id, name, address });
    });
});

// Delete (Bir müşteriyi silme)
app.delete('/customers/:id', verifyToken, (req, res) => {
    const { id } = req.params;
    const sql = 'DELETE FROM Customers WHERE CustomerID = ?';
    connection.query(sql, [id], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        if (results.affectedRows === 0) {
            res.status(404).send({ message: 'Müşteri bulunamadı.' });
            return;
        }
        res.status(200).send({ message: 'Müşteri silindi.' });
    });
});

app.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor.`);
});


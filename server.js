const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = 'chave_secreta_super_segura_aqui';

// Inicialização do Banco de Dados SQLite
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error('Erro ao abrir o banco de dados', err.message);
    else {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            balance REAL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount REAL,
            type TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// Middleware de Autenticação
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Acesso negado.' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Sessão inválida.' });
        req.user = user;
        next();
    });
}

// Rota: Cadastro
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'Preencha todos os campos.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`, 
            [username, email, hashedPassword], 
            function(err) {
                if (err) return res.status(400).json({ error: 'Usuário ou E-mail já existem.' });
                res.json({ message: 'Conta criada com sucesso!' });
            }
        );
    } catch (err) {
        res.status(500).json({ error: 'Erro no servidor.' });
    }
});

// Rota: Login
app.post('/login', (req, res) => {
    const { login, password } = req.body; // login pode ser email ou username
    
    db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [login, login], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Usuário não encontrado.' });
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Senha incorreta.' });

        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token, message: 'Login realizado com sucesso!' });
    });
});

// Rota: Dados do Usuário
app.get('/me', authenticateToken, (req, res) => {
    db.get(`SELECT id, username, email, balance, created_at FROM users WHERE id = ?`, [req.user.id], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Usuário não encontrado.' });
        res.json(user);
    });
});

// Rota: Painel Administrativo - Modificar Saldo
app.post('/admin/balance', authenticateToken, (req, res) => {
    const { adminPassword, targetUsername, amount, action } = req.body;

    // Verificação da senha administrativa exigida
    if (adminPassword !== 'danixs010') {
        return res.status(403).json({ error: 'Senha administrativa incorreta.' });
    }

    db.get(`SELECT id, balance FROM users WHERE username = ?`, [targetUsername], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'Usuário alvo não encontrado.' });

        let newBalance = user.balance;
        let numAmount = parseFloat(amount);

        if (action === 'add') newBalance += numAmount;
        else if (action === 'remove') newBalance -= numAmount;
        else return res.status(400).json({ error: 'Ação inválida.' });

        db.run(`UPDATE users SET balance = ? WHERE id = ?`, [newBalance, user.id], function(err) {
            if (err) return res.status(500).json({ error: 'Erro ao atualizar saldo.' });
            
            // Registra histórico
            db.run(`INSERT INTO transactions (user_id, amount, type) VALUES (?, ?, ?)`, [user.id, numAmount, action]);
            res.json({ message: `Saldo atualizado com sucesso. Novo saldo: R$ ${newBalance.toFixed(2)}` });
        });
    });
});

app.listen(3000, () => console.log('Servidor rodando na porta 3000'));
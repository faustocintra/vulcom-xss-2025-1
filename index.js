const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const helmet = require('helmet')

const app = express();

// Solução para XSS usando Helmet
// app.use(helmet())
// app.use(helmet.contentSecurityPolicy({
//   directives: {
//     defaultSrc: ["'self'"],   // Aceita apenas recursos do próprio domínio
//     scriptSrc: ["'self'"],    // Bloqueia scripts inline e externos
//   }
// }))

const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Criar tabela de comentários vulnerável
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        // res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: false }); // VULNERÁVEL A XSS 🚨
        // Cookie protegido contra XSS
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: true }); // SEGURO 🚨
    }
    next();
});

// Rota principal
app.get('/', (req, res) => {
    db.all("SELECT * FROM comments", [], (err, rows) => {
        if (err) {
            return res.send('Erro ao carregar comentários');
        }
        res.render('comments', { comments: rows });
    });
});

// Rota para enviar comentários (VULNERÁVEL a XSS 🚨)
app.post('/comment', (req, res) => {
    const { content } = req.body;
    // Solução para XSS usando DOMPurify
    // db.run("INSERT INTO comments (content) VALUES (?)", [DOMPurify.sanitize(content)], (err) => {
    
    db.run("INSERT INTO comments (content) VALUES (?)", [content], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});

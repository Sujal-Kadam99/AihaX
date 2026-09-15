const express = require('express');
const app = express();
app.use(express.json());

const users = [{ username: 'admin', password: 'secretpassword' }];

app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    
    // Simulate mongo query operator parsing
    const match = users.find(u => {
        let uMatch = false;
        let pMatch = false;
        
        if (username === undefined) uMatch = true;
        else if (typeof username === 'string') uMatch = (u.username === username);
        else if (username && username.$ne !== undefined) uMatch = (u.username !== username.$ne);
        
        if (typeof password === 'string') pMatch = (u.password === password);
        else if (password && password.$ne !== undefined) pMatch = (u.password !== password.$ne);
        
        return uMatch && pMatch;
    });

    if (match) res.send('Logged in as ' + match.username);
    else res.status(401).send('Invalid credentials');
});

app.listen(5003, () => console.log('Mock NoSQL target on 5003'));

const express = require('express')
const cors = require('cors')
const routes = require('./routes')

const app = express();
const PORT = 5000;

app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(express.json());
app.use('/api', routes);

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));


require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const webRoutes = require('./routes/web');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(bodyParser.json());
app.use('/api', webRoutes); // Like Laravel route group prefix

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


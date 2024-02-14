const express = require("express");
const cors = require('cors');
const mongoose = require("mongoose");
const rootRouter = require("./routes/index");
const port =3000;
require("dotenv").config();
const MongoDBURL = process.env.MONGODB_URL;


const app = express();
app.use(express.json());

app.use("/api/v1", rootRouter);

mongoose.connect(MongoDBURL,{
    useNewUrlParser: true,
    useUnifiedTopology: true})

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
})
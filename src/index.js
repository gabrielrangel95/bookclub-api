import * as dotenv from "dotenv";
dotenv.config();
import express from "express";
import db from "./models";
import routes from "./routes";
import cors from "cors";
const app = express();

app.use(express.json());
app.use(routes);
app.use(cors("*"));

app.listen(3333, async () => {
  try {
    await db.sequelize.authenticate();
    console.log("App running and db connected");
  } catch (error) {
    console.log("Error running app: ", error);
  }
});

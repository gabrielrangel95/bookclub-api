import { Book, Author } from "../models";
import { Op } from "sequelize";

class SearchController {
  async get(req, res) {
    try {
      const { name } = req.query;
      const authors = await Author.findAll({
        where: {
          name: {
            [Op.iLike]: `%${name}%`,
          },
        },
      });
      const books = await Book.findAll({
        where: {
          name: {
            [Op.iLike]: `%${name}%`,
          },
        },
      });
      return res.json({ authors, books });
    } catch (error) {
      return res.status(400).json({ error: error?.message });
    }
  }
}

export default new SearchController();

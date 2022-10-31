import { User, Book, UserBook, Author } from "../models";
import * as Yup from "yup";

class UserBookController {
  async create(req, res) {
    try {
      const schema = Yup.object().shape({
        book_id: Yup.number().required("Id do livro é obrigatório."),
      });

      await schema.validate(req.body);

      const user = await User.findByPk(req.userId);
      if (!user) {
        return res.status(404).json({ error: "Usuário não encontrado" });
      }

      const book = await Book.findByPk(req.body.book_id);
      if (!book) {
        return res.status(404).json({ error: "Livro não encotrado" });
      }

      const alreadyExists = await UserBook.findOne({
        where: {
          user_id: req.userId,
          book_id: req.body.book_id,
        },
      });

      if (alreadyExists) {
        return res.status(400).json({ error: "Livro já favoritado" });
      }

      const userbook = new UserBook({
        user_id: req.userId,
        book_id: req.body.book_id,
      });

      await userbook.save();

      return res.json(userbook);
    } catch (error) {
      return res.status(400).json({ error: error?.message });
    }
  }

  async getAll(req, res) {
    try {
      const userbooks = await UserBook.findAll({
        where: {
          user_id: req.userId,
        },
        include: [
          {
            model: Book,
            as: "book",
            include: [
              {
                model: Author,
                as: "author",
                attributes: ["name"],
              },
            ],
          },
        ],
      });

      return res.json(userbooks);
    } catch (error) {
      return res.status(400).json({ error: error?.message });
    }
  }

  async delete(req, res) {
    try {
      if (!req.params.id) {
        return res.status(400).json({ error: "Id do livro é obrigatório." });
      }

      const userbook = await UserBook.findByPk(req.params.id);

      if (!userbook) {
        return res.status(404).json({ error: "Livro não encontado." });
      }

      if (userbook.user_id !== req.userId) {
        return res
          .status(401)
          .json({ error: "Registro não pertence ao usuário" });
      }

      await userbook.destroy();

      return res.json({ success: true });
    } catch (error) {
      return res.status(400).json({ error: error?.message });
    }
  }
}

export default new UserBookController();

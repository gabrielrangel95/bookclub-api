import { Book, Category, Author, UserBook } from "../models";
import * as Yup from "yup";

class BookController {
  async create(req, res) {
    try {
      const schema = Yup.object().shape({
        category_id: Yup.number().required("Categoria é obrigatório"),
        author_id: Yup.number().required("Autor é obrigatório"),
        name: Yup.string().required(),
        cover_url: Yup.string().url("Cover deve ser uma URL válida."),
        release_date: Yup.date(
          "Data de lançamento deve ser um formato de data válido"
        ),
        pages: Yup.number(),
        synopsis: Yup.string(),
        highlighted: Yup.boolean(),
      });

      await schema.validate(req.body);

      const { category_id, author_id } = req.body;

      const category = await Category.findByPk(category_id);

      if (!category) {
        return res.status(404).json({ error: "Categoria não encontrada" });
      }

      const author = await Author.findByPk(author_id);

      if (!author) {
        return res.status(404).json({ error: "Autor não encontrada" });
      }

      const book = await new Book({
        ...req.body,
      });

      await book.save();

      return res.json(book);
    } catch (error) {
      return res.status(400).json({ error: error?.message });
    }
  }

  async update(req, res) {
    try {
      const { id } = req.params;
      if (!id) {
        return res.status(400).json({ error: "Id é obrigatório" });
      }

      const schema = Yup.object().shape({
        category_id: Yup.number(),
        author_id: Yup.number(),
        name: Yup.string(),
        cover_url: Yup.string(),
        release_date: Yup.date(
          "Data de lançamento deve ser um formato de data válido"
        ),
        pages: Yup.number(),
        synopsis: Yup.string(),
        highlighted: Yup.boolean(),
      });

      await schema.validate(req.body);

      const book = await Book.findByPk(id);

      const { category_id, author_id } = req.body;

      if (category_id) {
        const category = await Category.findByPk(category_id);

        if (!category) {
          return res.status(404).json({ error: "Categoria não encontrada" });
        }
      }

      if (author_id) {
        const author = await Author.findByPk(author_id);

        if (!author) {
          return res.status(404).json({ error: "Autor não encontrado" });
        }
      }

      await book.update({
        ...req.body,
      });

      await book.save();

      return res.json(book);
    } catch (error) {
      return res.status(400).json({ error: error?.message });
    }
  }

  async findAll(req, res) {
    const { highlighted, category_id } = req.query;
    try {
      const where = {};

      if (highlighted) {
        where.highlighted = true;
      }

      if (category_id) {
        where.category_id = Number(category_id);
      }

      const books = await Book.findAll({
        where,
        include: [
          {
            model: Author,
            as: "author",
            attributes: ["name", "id"],
          },
          {
            model: Category,
            as: "category",
            attributes: ["name", "id"],
          },
        ],
      });
      return res.json(books);
    } catch (error) {
      return res.status(400).json({ error: error?.message });
    }
  }

  async findOne(req, res) {
    const { id } = req.params;
    try {
      if (!id) {
        return res.status(400).json({ error: "Id é obrigatório" });
      }

      const book = await Book.findByPk(id, {
        include: [
          {
            model: Author,
            as: "author",
            attributes: ["name", "id"],
          },
          {
            model: Category,
            as: "category",
            attributes: ["name", "id"],
          },
        ],
      });

      const isFavorite = await UserBook.findOne({
        where: {
          user_id: req.userId,
          book_id: id,
        },
      });

      return res.json({
        book,
        favorite: isFavorite,
      });
    } catch (error) {
      return res.status(400).json({ error: error?.message });
    }
  }
}

export default new BookController();

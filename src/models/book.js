"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
  class Book extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      this.belongsTo(models.Author, { foreignKey: "author_id", as: "author" });
      this.belongsTo(models.Category, {
        foreignKey: "category_id",
        as: "category",
      });
      this.hasMany(models.UserBook, {
        foreignKey: "book_id",
        as: "book",
      });
    }
  }
  Book.init(
    {
      name: DataTypes.STRING,
      cover_url: DataTypes.STRING,
      release_date: DataTypes.DATE,
      pages: DataTypes.INTEGER,
      synopsis: DataTypes.TEXT,
      highlighted: DataTypes.INTEGER,
    },
    {
      sequelize,
      modelName: "Book",
    }
  );
  return Book;
};

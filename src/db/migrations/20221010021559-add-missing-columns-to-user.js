"use strict";

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await Promise.all([
      queryInterface.addColumn("Users", "reset_password_token", {
        type: Sequelize.STRING,
      }),
      queryInterface.addColumn("Users", "reset_password_token_sent_at", {
        type: Sequelize.DATE,
      }),
      queryInterface.addColumn("Users", "avatar_url", {
        type: Sequelize.STRING,
      }),
    ]);
  },

  async down(queryInterface, Sequelize) {
    await Promise.all([
      queryInterface.removeColumn("Users", "reset_password_token"),
      queryInterface.removeColumn("Users", "reset_password_token_sent_at"),
      queryInterface.removeColumn("Users", "avatar_url"),
    ]);
  },
};

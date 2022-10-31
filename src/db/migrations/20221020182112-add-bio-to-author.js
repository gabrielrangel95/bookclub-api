"use strict";

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await Promise.all([
      queryInterface.addColumn("Authors", "bio", {
        type: Sequelize.TEXT,
      }),
    ]);
  },

  async down(queryInterface, Sequelize) {
    await Promise.all([queryInterface.removeColumn("Authors", "bio")]);
  },
};

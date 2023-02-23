"use strict";

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    return queryInterface.bulkInsert("Authors", [
      {
        id: 1,
        name: "J.K. Rowling",
        avatar_url:
          "https://m.media-amazon.com/images/S/amzn-author-media-prod/8cigckin175jtpsk3gs361r4ss._SX450_.jpg",
        bio: "Joanne Kathleen Rowling nasceu nos arredores de Bristol, na região de Gloucestershire, Inglaterra, em 31 de julho de 1965. Estudou Francês e Letras Clássicas na Universidade de Exeter. Em 1990, Rowling teve a idéia para a trama de Harry Potter, numa viagem de trem de Manchester para Londres. Sete anos depois, a primeira edição de Harry Potter e a Pedra Filosofal foi publicada na Inglaterra pela editora Bloomsbury, dando início ao maior fenômeno editorial de todos os tempos. J. K. Rowling ganhou, entre outros prêmios, o Nestlé Smarties Book Prize Gold Medal, o FCBC Children’s Book Prize, o Birmingham Cable Children’s Book Award e o cobiçado British Book Awards Children’s Book of the Year. Em 2003, a autora foi agraciada com o Prêmio Príncipe de Astúrias da Concórdia, um dos mais importantes do mundo, concedido pela Fundação Príncipe de Astúrias a pessoas, instituições ou grupos cujo trabalho tenha contribuído de forma exemplar e relevante para a fraternidade entre os homens e a luta contra a injustiça, a pobreza, a enfermidade e a ignorância. ",
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 2,
        name: "J. R. R. Tolkien",
        avatar_url:
          "https://m.media-amazon.com/images/I/71GP8lxqn0L._SX450_.jpg",
        bio: "John Ronald Reuel Tolkien,[1] CBE,[2] FRSL, conhecido internacionalmente por J. R. R. Tolkien (Bloemfontein, 3 de janeiro de 1892 — Bournemouth, 2 de setembro de 1973),[3] foi um escritor, professor universitário e filólogo britânico, nascido na atual África do Sul, que recebeu o título de doutor em Letras e Filologia pela Universidade de Liège e Dublin, em 1954,[4][5] e autor das obras como O Hobbit, O Senhor dos Anéis e O Silmarillion.[6] Em 28 de março de 1972, Tolkien foi nomeado Comendador da Ordem do Império Britânico pela Rainha Elizabeth II.",
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 3,
        name: "George R. R. Martin",
        avatar_url:
          "https://m.media-amazon.com/images/S/amzn-author-media-prod/1u8p8qq9fr3eq2ocgma6j56s0g._SX450_.jpg",
        bio: "George Raymond Richard Martin (Bayonne, 20 de setembro de 1948), nascido George Raymond Martin e mais conhecido como George R. R. Martin ou simplesmente GRRM, é um roteirista e escritor de ficção científica, terror e fantasia norte-americano. É mais conhecido por escrever a série de livros de fantasia épica As Crônicas de Gelo e Fogo. Em 2005, Lev Grossman da revista Time chamou Martin de o Tolkien americano,[1] e em 2011, ele foi incluído na lista da Time das 100 pessoas mais influentes do mundo.[2][3]",
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 4,
        name: "Napoleon Hill",
        avatar_url:
          "https://m.media-amazon.com/images/I/517LznLEhnL._SX450_.jpg",
        bio: "Napoleon Hill (Pound, 26 de outubro de 1883 - Carolina do Sul, 8 de novembro de 1970) foi um escritor estadunidense influente na área de autoajuda.[1] Foi assessor de Woodrow Wilson e Franklin Delano Roosevelt, presidentes dos Estados Unidos.[2] Dizia um dos seus compromissos: “o que a mente do homem pode conceber e acreditar, pode ser alcançada”.",
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 5,
        name: "Robert T. Kiyosaki",
        avatar_url:
          "https://m.media-amazon.com/images/I/31r-oQ3Y8YL._UY200_.jpg",
        bio: "Nasceu em Hilo, Hawaii, de ascendência Nipo-Americana, filho de Ralph H. Kiyosaki (1919-1991). Trabalhou na Standard Oil Company depois de ter se formado na Marinha Mercante, para poder viajar o mundo e conhecer os mercados emergentes. Foi para guerra do Vietnã pelos Fuzileiros Navais até 1974 para estudar liderança de tropas. Trabalhou na empresa Xerox até 1977 para aprender sobre vendas.",
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);
  },

  async down(queryInterface, Sequelize) {
    return queryInterface.bulkDelete("Authors", null, {});
  },
};

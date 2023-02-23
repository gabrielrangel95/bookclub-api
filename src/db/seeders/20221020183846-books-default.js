"use strict";

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    return queryInterface.bulkInsert("Books", [
      {
        author_id: 1,
        category_id: 3,
        name: "Harry Potter e a Pedra Filosofal",
        cover_url: "https://m.media-amazon.com/images/I/51lRMYwP-4L.jpg",
        release_date: new Date("08/12/2015"),
        pages: 312,
        synopsis:
          "Quando virou o envelope, com a mão trêmula, Harry viu um lacre de cera púrpura com um brasão; um leão, uma águia, um texugo e uma cobra circulando uma grande letra H. Harry Potter nunca havia ouvido falar de Hogwarts quando as cartas começaram a aparecer no capacho da Rua dos Alfeneiros, nº 4. Escritos a tinta verde-esmeralda em pergaminho amarelado com um lacre de cera púrpura, as cartas eram rapidamente confiscadas por seus pavorosos tio e tia. Então, no aniversário de onze anos de Harry, um gigante com olhos que luziam como besouros negros chamado Rúbeo Hagrid surge com notícias surpreendentes: Harry Potter é um bruxo e tem uma vaga na Escola de Magia e Bruxaria de Hogwarts. Uma incrível aventura está para começar!",
        highlighted: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        author_id: 1,
        category_id: 3,
        name: "Harry Potter e a Câmara Secreta",
        cover_url: "https://m.media-amazon.com/images/I/51PHM1T3wuL.jpg",
        release_date: new Date("08/12/2015"),
        pages: 354,
        synopsis:
          "Há uma trama, Harry Potter. Uma trama para fazer coisas terríveis acontecerem na Escola de Magia e Bruxaria de Hogwarts este ano.' O verão de Harry Potter incluiu o pior aniversário de todos, avisos macabros de um elfo doméstico chamado Dobby, e ser resgatado dos Dursleys por seu amigo Rony Weasley em um carro voador mágico! De volta à Escola de Magia e Bruxaria de Hogwarts para seu segundo ano, Harry ouve estranhos sussurros ecoando pelos corredores vazios - e então, os ataques começam! Estudantes são encontrados transformados em pedra... As previsões sinistras de Dobby parecem estar se tornando realidade.",
        highlighted: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        author_id: 1,
        category_id: 3,
        name: "Harry Potter e o prisioneiro de Azkaban",
        cover_url: "https://m.media-amazon.com/images/I/515TcMeZStL.jpg",
        release_date: new Date("08/12/2015"),
        pages: 448,
        synopsis:
          "Bem-vindo ao ônibus Nôitibus Andante, o transporte de emergência para bruxos e bruxas perdidos. Basta esticar a mão da varinha, subir a bordo e podemos levá-lo aonde quiser.' Quando o ônibus Nôitibus Andante surge repentinamente da escuridão e solta um guincho de seu freio bem à sua frente, mais um ano nada normal em Hogwarts começa para Harry Potter. Sirius Black, assassino em série fugitivo e seguidor do Lorde Voldemort, está à solta - e dizem que está indo atrás de Harry. Em sua primeira aula de Adivinhação, a professora Trelawney vê um agouro de morte nas folhas do chá de Harry... Mas talvez a parte mais assustadora seja os Dementadores patrulhando os pátios da escola, com seus beijos que sugam a alma",
        highlighted: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        author_id: 1,
        category_id: 3,
        name: "Harry Potter e o Cálice de Fogo",
        cover_url: "https://m.media-amazon.com/images/I/515pFJ2KfVL.jpg",
        release_date: new Date("08/12/2015"),
        pages: 753,
        synopsis:
          "Haverá três tarefas, espaçadas durante o ano letivo, que servirão para testar os campeões de diferentes maneiras... sua perícia em magia, sua coragem, seus poderes de dedução e, naturalmente, sua capacidade de enfrentar o perigo. O Torneio Tribruxo será realizado em Hogwarts. Apenas bruxos acima dos dezessete anos de idade podem se inscrever - mas isso não impede que Harry sonhe em vencer a competição. E então, no Dia das Bruxas, quando o Cálice de Fogo faz sua seleção, Harry se surpreende ao ver que seu nome é um dos que a taça mágica escolhe. Ele terá de enfrentar tarefas mortais, dragões e bruxos das trevas, mas com a ajuda de seus melhores amigos, Ron e Hermione, talvez ele consiga sair dessa - vivo!",
        highlighted: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        author_id: 1,
        category_id: 3,
        name: "Harry Potter e a Ordem da Fênix",
        cover_url: "https://m.media-amazon.com/images/I/519namgWJTL.jpg",
        release_date: new Date("08/12/2015"),
        pages: 987,
        synopsis:
          "Você está compartilhando os pensamentos e emoções do Lorde das Trevas. O diretor acha que é desaconselhável que isto continue a acontecer. E quer que eu lhe ensine como fechar a mente ao Lorde das Trevas.'Tempos sombrios se abateram sobre Hogwarts. Depois do ataque dos Dementadores ao seu primo Dudley, Harry Potter sabe que Voldemort fará tudo para encontrá-lo. Muitos negam o retorno do Lorde das Trevas, mas Harry não está sozinho: uma ordem secreta se reúne no Largo Grimmauld para fazer frente às forças sombrias. Harry precisa permitir que o professor Snape o ensine a se proteger dos vorazes ataques de Voldemort à sua mente. Mas eles estão ficando cada vez mais fortes, e o tempo de Harry está acabando...",
        highlighted: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        author_id: 1,
        category_id: 3,
        name: "Harry Potter e o enigma do Príncipe",
        cover_url: "https://m.media-amazon.com/images/I/519WGXbWCaL.jpg",
        release_date: new Date("08/12/2015"),
        pages: 651,
        synopsis:
          "Lá estava, pairando no céu sobre a escola: o crânio verde flamejante com uma língua de cobra, a marca deixada pelos Comensais da Morte sempre que entravam em um prédio... sempre que matavam... Quando Dumbledore chega à Rua dos Alfeneiros numa certa noite de verão para buscar Harry Potter, a mão com que segura a varinha está enrugada e enegrecida, mas ele não revela o motivo. Segredos e suspeitas se espalham pelo Mundo Bruxo, e a própria Hogwarts não é mais segura. Harry está convencido de que Malfoy porta a Marca Negra: há um Comensal da Morte entre eles. Harry precisará de magia poderosa e amigos verdadeiros para explorar os segredos mais sombrios de Voldemort, e Dumbledore se prepara para encarar seu destino...",
        highlighted: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        author_id: 1,
        category_id: 3,
        name: "Harry Potter e as Relíquias da Morte",
        cover_url: "https://m.media-amazon.com/images/I/51-lxNye+pL.jpg",
        release_date: new Date("08/12/2015"),
        pages: 754,
        synopsis:
          "Entreguem-me Harry Potter, disse a voz de Voldemort, e ninguém sairá ferido. Entreguem-me Harry Potter, e não tocarei na escola. Entreguem-me Harry Potter, e serão recompensados. Ao subir no sidecar da moto de Hagrid e subir aos céus, deixando a Rua dos Alfeneiros pela última vez, Harry Potter sabe que o lorde Voldemort e os Comensais da Morte estão em seu encalço. O feitiço de proteção que manteve Harry seguro até o momento foi quebrado, mas ele não pode mais se esconder. O Lorde das Trevas está incutindo medo em tudo que Harry ama e, para detê-lo, Harry terá de encontrar e destruir as Horcruxes que restaram. A batalha final está para começar - Harry precisa enfrentar seu inimigo...",
        highlighted: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        author_id: 5,
        category_id: 1,
        name: "Pai Rico, Pai Pobre",
        cover_url:
          "https://m.media-amazon.com/images/I/519kRFUvDOL._SX356_BO1,204,203,200_.jpg",
        release_date: new Date("05/09/2018"),
        pages: 336,
        synopsis:
          "A escola prepara as crianças para o mundo real?  Essa é a primeira pergunta com a qual o leitor se depara neste livro.  O recado é ousado e direto: boa formação e notas altas não bastam para assegurar o sucesso de alguém. O mundo mudou; a maioria dos jovens tem cartão de crédito, antes mesmo de concluir os estudos, e nunca teve aula sobre dinheiro, investimentos, juros etc. Ou seja, eles vão para a escola, mas continuam financeiramente improficientes, despreparados para enfrentar um mundo que valoriza mais as despesas do que a poupança. Para o autor, o conselho mais perigoso que se pode dar a um jovem nos dias de hoje é: “Vá para a escola, tire notas altas e depois procure um trabalho seguro.”  O fato é que agora as regras são outras, e não existe mais emprego garantido para ninguém.  Pai Rico, Pai Pobre demonstra que a questão não é ser empregado ou empregador, mas ter o controle do próprio destino ou delegá-lo a alguém.  É essa a tese de Robert Kiyosaki neste livro substancial e visionário.  Para ele, a formação proporcionada pelo sistema educacional não prepara os jovens para o mundo que encontrarão depois de formados E como os pais podem ensinar aos filhos o que a escola relega? Essa é outra das muitas perguntas que o leitor encontra em Pai Rico, Pai Pobre. Nesse sentido, a proposta do autor é facilitar a tarefa dos pais. Quem entende de contabilidade deve esquecer seus conhecimentos acadêmicos, pois muitas das teorias expostas por Robert Kiyosaki contrariam os princípios contábeis comumente aceitos, e apresentam uma valiosa e moderna percepção do modo como se realizam os investimentos. A sociedade sofre mudanças radicais e, talvez, de proporções maiores do que as ocorridas em séculos passados. Não existe bola de cristal, mas algo é certo: a perspectiva global de transformações transcende nossa realidade imediata. Aconteça o que acontecer, só existem duas alternativas: segurança ou independência financeira. E o objetivo de Pai Rico, Pai Pobre é instruir o leitor e despertar sua inteligência financeira e a de seus filhos.",
        highlighted: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        author_id: 4,
        category_id: 1,
        name: "Mais esperto que o Diabo: O mistério revelado da liberdade e do sucesso",
        cover_url:
          "https://m.media-amazon.com/images/I/51b6LT-tHwL._SX331_BO1,204,203,200_.jpg",
        release_date: new Date("10/07/2014"),
        pages: 208,
        synopsis:
          "Neste livro, inédito no Brasil, você vai descobrir, após 75 anos de segredo, por meio dessa entrevista exclusiva que Napoleon Hill fez, quebrando o código secreto da mente do Diabo: Quem é o Diabo? Onde ele habita? Quais suas principais armas mentais? Quem são os alienados e de que forma eles ou elas se alienam? De que forma o Diabo influencia a nossa vida do dia a dia? Como a sua dominação influencia nossas atitudes? O que é o medo? Como nossos líderes religiosos e nossos professores são afetados pelo Diabo? Quais as armas que nós, seres humanos, possuímos para combater a dominação do Diabo? Qual a visão do Diabo sobre a energia sexual? Como buscar uma vida cheia de realizações, valorizando a felicidade e a liberdade? Essas perguntas e muitas outras são respondidas pelo próprio Diabo, que se autodenomina Sua Majestade, de acordo com Napoleon Hill. O seu propósito, escrito com suas próprias palavras, é ajudar o ser humano a descobrir o seu real potencial, desvendando as armadilhas mentais que os homens e as mulheres deste mundo criam para si mesmos, sabotando a sua própria liberdade e o seu próprio direito de viver uma vida cheia de desafios, alegria e liberdade. Escrito em 1938, após uma das maiores crises econômicas, e precedendo a Segunda Guerra Mundial, este livro não somente é uma fonte de inspiração e coragem, mas deve ser considerado um manual para todas aquelas pessoas que desejam.",
        highlighted: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);
  },

  async down(queryInterface, Sequelize) {
    return queryInterface.bulkDelete("Books", null, {});
  },
};

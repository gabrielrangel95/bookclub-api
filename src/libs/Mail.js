import NodeMailJet from "node-mailjet";

const mailJet = NodeMailJet.apiConnect(
  process.env.MAILJET_API_KEY,
  process.env.MAILJET_SECRET_KEY
);

class Mail {
  async sendForgotPasswordMail(email, name, token) {
    try {
      const result = await mailJet.post("send", { version: "v3.1" }).request({
        Messages: [
          {
            From: {
              Email: "contato@mapadaprogramacao.com.br",
              Name: "BookClub",
            },
            To: [
              {
                Email: email,
                Name: name,
              },
            ],
            TemplateID: 4319004,
            TemplateLanguage: true,
            Subject: "Alteração de Senha",
            Variables: {
              name: name,
              token: token,
            },
          },
        ],
      });
      return result;
    } catch (error) {
      return { error };
    }
  }
}

export default new Mail();

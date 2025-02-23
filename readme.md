# Security Scanner
Um scanner de segurança em Python pra verificar vulnerabilidades no seu computador, como acesso não autorizado a câmera e microfone, conexões de rede suspeitas e possíveis malwares. Feito com uma interface gráfica moderna usando CustomTkinter.

## O que ele faz
- **Câmera e Microfone**: Checa se processos suspeitos estão acessando dispositivos de câmera ou microfone.
- **Conexões de Rede**: Identifica conexões ativas com IPs externos que podem indicar espiões ou vazamentos de dados.
- **Malwares**: Procura processos com nomes associados a malwares conhecidos (lista básica, pode ser expandida).
- **Relatório**: Gera um arquivo `security_report.txt` com os resultados do scan.

## Como usar
1. **Pré-requisitos**: Python 3.x instalado.
  
  
**Uso**: Clique em "Iniciar Escaneamento" na interface para verificar seu sistema. Os resultados aparecem na tela e são salvos em `security_report.txt`.

## Features
- Interface gráfica moderna e escura com tema verde.
- Resultados em tempo real com cores (verde pra seguro, vermelho pra alerta).
- Barra de progresso durante o escaneamento.
- Relatório automático salvo como arquivo de texto.

## Tecnologias
- Python 3
- CustomTkinter (interface gráfica)
- psutil (checar processos e rede)
- socket (análise de conexões)

## Contribuições
Se quiser ajudar a melhorar, é só abrir um pull request ou criar uma issue com sugestões. Ideias pra expandir:
- Adicionar mais assinaturas de malwares.
- Melhorar a detecção de câmera/microfone com APIs específicas.
- Incluir checagem de arquivos no disco.

## Autor
- euuCode - [https://github.com/euuCode](https://github.com/euuCode)

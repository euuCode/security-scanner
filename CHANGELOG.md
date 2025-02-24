# Changelog - Security Scanner

## [1.1.0] - 2025-02-24
### Adicionado
- Scanner de arquivos com checagem de hashes (SHA-256) pra detectar possíveis malwares.
- Campo de entrada e botão "Selecionar Pasta" pra escolher pastas ou arquivos pra escanear.
- Botões separados: "Scanner de Intrusos" (pra câmera, rede, malwares) e "Scanner de Arquivos", tornando o programa mais modular.

### Melhorado
- Interface gráfica mais profissional com tema escuro, botões coloridos e feedback visual.
- Bloqueio da área de texto de resultados pra evitar edição pelo usuário.
- Performance do scan de arquivos, limitando a 50 arquivos por pasta e tratando erros melhor.
- Relatórios salvos como `intruders_report.txt` e `files_report.txt` no Desktop.

### Corrigido
- Erros de importação de `tkinter` ao usar `customtkinter`.

## [1.0.0] - [20/02/2025]
### Lançado
- Versão inicial com scans de câmera/microfone, redes e malwares em processos.
- Interface gráfica básica com `customtkinter`.


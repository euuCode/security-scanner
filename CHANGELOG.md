# Changelog - Security Scanner

## Security Scanner v1.2.0 - Changelog

## Novas Funcionalidades
- Adicionado botão "Cancelar" nas abas "Scanner de Computador" e "Scanner de Arquivos" para interromper scans a qualquer momento.
- Criada aba "Histórico de Logs" para exibir, baixar (PDF), e excluir logs de scans anteriores.
- Melhoria na geração e exibição de logs após cada scan, com timestamp e tipo.

## Correções
- Corrigido erro de sintaxe em `check_files` (linha 313).
- Garantida compatibilidade com ambientes Linux/Windows para salvar logs.


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

## [1.0.0] - 2025-02-15
### Lançado
- Versão inicial com scans de câmera/microfone, redes e malwares em processos.
- Interface gráfica básica com `customtkinter`.


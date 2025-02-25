# Security Scanner - by euuCode

![Security Scanner Screenshot](screenshot.png) <!-- Substitua por uma imagem real do visual do programa -->

O **Security Scanner** é uma ferramenta de código aberto para análise de segurança em computadores e arquivos, projetada para detectar atividades suspeitas (câmera/microfone, redes, malwares) e arquivos potencialmente perigosos (baseados em extensões). Feito com uma interface gráfica moderna usando CustomTkinter.

## O que ele faz
- **Câmera e Microfone**: Checa se processos suspeitos estão acessando dispositivos de câmera ou microfone.
- **Conexões de Rede**: Identifica conexões ativas com IPs externos que podem indicar espionagem ou vazamentos de dados.
- **Malwares**: Procura por processos com nomes associados a malwares conhecidos (lista básica, pode ser expandida).
- **Relatórios**: Gera logs automáticos salvos na aba "Histórico de Logs", com opção de download em PDF.

## Como usar
### Pré-requisitos
- Python 3.x instalado.

### Uso
- Clone o repositório:
git clone https://github.com/euuCode/security-scanner.git
cd security-scanner

- Instale as dependências:
pip install psutil customtkinter reportlab
- Clique em "Escanear Computador" ou "Escanear Arquivos" na interface para verificar o sistema. Os resultados aparecem na tela e são salvos no histórico.

## Características
- Interface gráfica moderna e escura com tema verde.
- Resultados em tempo real com cores (verde para seguro, vermelho para alerta).
- Barra de progresso durante o escaneamento.
- Opções para pausar, retomar, e cancelar scans.
- Histórico de logs com download em PDF e exclusão.
- Design responsivo e intuitivo.

## Tecnologias
- **Python**: Linguagem principal.
- **Psutil**: Para monitorar processos, redes, e dispositivos.
- **CustomTkinter**: Para a interface gráfica moderna.
- **Reportlab**: Para gerar relatórios em PDF.

## Changelog
Consulte os [releases](https://github.com/euuCode/security-scanner/releases) para detalhes das atualizações. Última versão: [v1.1.0](https://github.com/euuCode/security-scanner/releases/tag/v1.1.0).

## Próximos Passos
- Integração com VirusTotal para análise avançada de arquivos.
- Configurações personalizáveis (limite de arquivos, extensões suspeitas).
- Progresso real nas barras de progresso.

## Contribuições
Contribuições são bem-vindas! Abra issues para bugs ou sugestões, e envie pull requests para melhorias. Siga o código de conduta no [CONTRIBUTING.md](CONTRIBUTING.md) (crie este arquivo com regras básicas, se não existir).

## Licença
Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## Contato
- GitHub: [euuCode](https://github.com/euuCode)
- Email: marcioh22007@gmail.com

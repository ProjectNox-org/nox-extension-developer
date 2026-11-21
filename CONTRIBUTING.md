# Como contribuir

Para a versão em inglês, consulte [CONTRIBUTING.en.md](CONTRIBUTING.en.md).

1. Leia [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) e [SECURITY.md](SECURITY.md).
2. Para erros, melhorias, compatibilidade ou documentação, abra uma issue usando o modelo apropriado. Não publique vulnerabilidades, segredos ou dados pessoais em issues públicas.
3. Descreva o problema e a mudança proposta. Para mudanças maiores, discuta a abordagem antes de implementá-la.
4. Faça alterações focadas e acrescente ou atualize testes e documentação quando necessário.
5. Execute `python3 -m unittest discover -s tests -v` na raiz do projeto.
6. Abra um pull request com resumo, motivação, testes, compatibilidade e riscos. Remova segredos e dados pessoais de exemplos e logs.

## Versionamento (`MAJOR.MINOR.PATCH`)

- **MAJOR (`X.0.0`):** grandes atualizações, reformulações e mudanças significativas na arquitetura ou nas funcionalidades.
- **MINOR (`X.Y.0`):** atualizações importantes, novas funcionalidades e melhorias relevantes mantendo foco em compatibilidade.
- **PATCH (`X.Y.Z`):** correções de bugs, vulnerabilidades de segurança e ajustes pontuais.

Para problemas de segurança, siga [SECURITY.md](SECURITY.md), não uma issue pública.

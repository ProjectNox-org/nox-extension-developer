# Guia de instalação e uso

Nox Extension Developer é uma skill para criar, corrigir, manter, migrar ou revisar extensões Keiyoushi (mangá), Yuzono (anime) e plugins LNReader (novels). O agente consulta documentação oficial antes de editar e deve respeitar o repositório e o escopo autorizados.

## Dependências

- Python 3, Git, conexão HTTPS e acesso de leitura aos repositórios oficiais para obter referências atuais.
- Para compilar mangá ou anime, Android SDK, Java e demais componentes exigidos pelo repositório de destino. Para LNReader, Node.js e dependências locais definidas pelo projeto.
- As versões de Java, Android SDK, Node.js, bibliotecas e APIs dependem do projeto e do commit upstream. Confira os arquivos de build, as versões locais e a documentação oficial; não suponha uma versão universal.
- A primeira consulta exige rede. Offline, somente um snapshot completo e íntegro, obtido anteriormente, pode ser usado; ele pode estar desatualizado.

A skill não instala pacotes nem inicia serviços. Não aceite licenças nem instale componentes sem autorização.

## Preparação por sistema

Confira primeiro as ferramentas existentes. Em Linux e macOS, execute `python3 --version`, `git --version`, `java -version` e, se necessário para LNReader ou NPX, `node --version` e `npm --version`. No PowerShell, use `python --version`, `git --version`, `java -version`, `node --version` e `npm --version`. Ausência de Java ou Node.js só impede tarefas que precisem deles.

- **Arch Linux:** instale apenas componentes ausentes pelos [repositórios oficiais e pacman](https://wiki.archlinux.org/title/Pacman); consulte [Java](https://wiki.archlinux.org/title/Java) quando o projeto exigir JDK.
- **Debian/Ubuntu:** use os repositórios e instruções oficiais de [Debian](https://www.debian.org/doc/manuals/debian-reference/ch02.en.html) ou [Ubuntu](https://documentation.ubuntu.com/server/how-to/software/package-management/). Confira a versão do JDK exigida pelo projeto.
- **Fedora:** use [DNF e os repositórios oficiais](https://docs.fedoraproject.org/en-US/quick-docs/dnf/). Confira a versão do JDK exigida pelo projeto.
- **Windows:** obtenha Python em [python.org](https://www.python.org/downloads/), Git em [git-scm.com](https://git-scm.com/downloads), e Node.js, quando necessário, em [nodejs.org](https://nodejs.org/en/download). Para o JDK, escolha uma distribuição confiável compatível com o projeto, como [OpenJDK](https://openjdk.org/install/). Confira o PATH em uma nova sessão do PowerShell.
- **macOS:** obtenha ferramentas de fontes oficiais: [Python](https://www.python.org/downloads/), [Git](https://git-scm.com/downloads), [OpenJDK](https://openjdk.org/install/) e [Node.js](https://nodejs.org/en/download), conforme necessário. Confira o PATH em um novo terminal.

Exemplos para instalar Git, Python e, somente se precisar de NPX ou LNReader, Node.js e npm. Revise o comando e peça autorização administrativa antes de executá-lo; instale apenas os pacotes ausentes:

```sh
# Arch Linux
sudo pacman -S --needed git python nodejs npm
# Debian / Ubuntu
sudo apt update && sudo apt install git python3 nodejs npm
# Fedora
sudo dnf install git python3 nodejs npm
```

Para Windows e macOS, siga os instaladores oficiais ligados acima. Confira as versões após instalar. Estes exemplos não foram testados em todas as distribuições; o JDK deve corresponder ao projeto de destino.

Instalações e mudanças que exigem privilégios administrativos dependem de consentimento explícito. Linux foi testado localmente; as orientações para Windows e macOS não foram testadas.

## Android SDK, quando necessário

Para builds Android, confira primeiro o JDK exigido pelo projeto com `java -version` e `javac -version`. Use uma instalação existente compatível. Caso falte, instale uma distribuição confiável da versão exigida, com autorização.

Obtenha [Android SDK Command-Line Tools](https://developer.android.com/studio#command-line-tools-only) para seu sistema ou use uma instalação existente do Android Studio. Siga a [estrutura oficial de instalação do sdkmanager](https://developer.android.com/tools/sdkmanager): `cmdline-tools/latest/bin` deve conter `sdkmanager` (no Windows, `sdkmanager.bat`). Configure o caminho do SDK e o PATH conforme a [documentação oficial](https://developer.android.com/tools/variables); evite substituir configurações existentes.

No terminal, execute `sdkmanager --list` para identificar pacotes disponíveis e instalados. No PowerShell, use `sdkmanager.bat --list` se necessário. Consulte os arquivos do projeto para escolher versões de `platforms;android-<API>` e `build-tools;<VERSÃO>`; não suponha versões universais. Após autorização, instale somente os pacotes necessários, substituindo os marcadores por valores verificados:

```sh
sdkmanager "platform-tools" "platforms;android-<API>" "build-tools;<VERSÃO>"
```

`platform-tools` contém ADB; instale-o se necessário e verifique com `adb version` e `adb devices`. No Windows, use `sdkmanager.bat` e `adb.exe` quando apropriado. Execute `sdkmanager --licenses` para examinar licenças pendentes e aceite-as somente com autorização. O emulador é opcional: instale `emulator` e uma imagem de sistema apenas se a tarefa exigir testes em emulador; siga o [guia oficial](https://developer.android.com/studio/run/managing-avds). Um build ou uma lista vazia de dispositivos não confirma funcionamento da extensão.

## Alternativa com NPX

Esta alternativa requer Node.js e npm. A descoberta e a instalação por cópia local foram testadas com Skills CLI 1.8.1 no Linux; outros sistemas e o fluxo remoto não foram verificados nesse teste. O [Skills CLI oficial](https://github.com/vercel-labs/skills/blob/main/docs/commands.md) aceita caminho local ou URL remota. Revise o pacote, o código da CLI e a origem antes de executar: `npx` pode baixar e executar código do registro npm. Veja também [npm exec](https://docs.npmjs.com/cli/commands/npm-exec/). Não use opções que aceitem alterações automaticamente sem revisão.

No diretório permanente da skill, a fonte local é `.`:

```sh
npx skills add . --global --agent opencode
```

Para uma fonte remota, substitua `<URL-CONFIAVEL-DO-REPOSITORIO>` pela URL verificada de uma publicação autorizada:

```sh
npx skills add <URL-CONFIAVEL-DO-REPOSITORIO> --global --agent opencode
```

No PowerShell, substitua o marcador pela URL real, sem os sinais `<` e `>`. `--global` seleciona instalação de usuário, não privilégios de administrador; `--agent` seleciona o agente. Confirme os identificadores e o comportamento na documentação atual. A CLI é alternativa ao instalador deste projeto e pode criar arquivos ou links em locais diferentes: revise o destino e conflitos antes de confirmar. Não sobrescreva configurações ou credenciais existentes.

## Instalação

Extraia uma cópia confiável do pacote em um diretório permanente de usuário. Entre no diretório que contém `SKILL.md` e `scripts/install.py`. Preserve esse diretório: o instalador cria um link para ele, não uma cópia.

No Linux ou macOS, para OpenCode:

```sh
mkdir -p ~/.config/opencode/skills
python3 scripts/install.py opencode
```

No Windows nativo, os scripts de referências não funcionam porque dependem de `fcntl` e operações POSIX. Use WSL com Linux para instalar o agente e executar os scripts. O exemplo de link abaixo é apenas referência e não comprova funcionamento nativo:

```powershell
New-Item -ItemType Directory -Force -Path "$HOME\.config\opencode\skills" | Out-Null
python scripts/install.py opencode
```

O instalador exige que o diretório de skills já exista. Ele não substitui um arquivo ou link existente e informa quando o link correto já existe. A criação de links no Windows depende das permissões e configurações do sistema. Não eleve privilégios nem altere políticas de segurança sem consentimento explícito. Se a criação falhar, consulte a documentação da plataforma e solicite autorização antes de qualquer mudança administrativa.

Reinicie o OpenCode ou abra uma nova sessão. Peça explicitamente `Use nox-extension-developer` e confirme que a ferramenta de skills carregou a skill. O carregamento automático depende do agente.

Para atualizar, faça backup do diretório e das alterações locais antes de seguir as instruções da nova versão. O instalador não sobrescreve uma instalação existente. Para remover, confirme que o destino é o link criado para este diretório e remova somente esse link. Preserve o diretório canônico e o cache até verificar que não são mais necessários.

## Instalação com ajuda de IA

Revise e forneça ao agente o arquivo [prompts/install-pt-BR.txt](../../prompts/install-pt-BR.txt). Informe o diretório permanente da skill e a plataforma escolhida. Revise os comandos propostos antes de autorizá-los. O prompt não concede acesso administrativo nem autoriza sobrescrever configurações ou credenciais.

## Utilização

Exemplo: `Use nox-extension-developer para corrigir esta extensão Keiyoushi sem migrar sua API.` Informe o repositório, o problema, o site e os limites de acesso quando aplicável. Para anime, indique Yuzono; para novels, LNReader. Se houver ambiguidade, o agente deve perguntar.

O fluxo exige sincronizar as referências oficiais do ecossistema antes de editar. No diretório da skill:

```sh
python3 scripts/references.py sync keiyoushi
python3 scripts/references.py sync yuzono
python3 scripts/references.py sync lnreader
```

Execute apenas o comando correspondente à tarefa; no Windows, use o comando Python 3 disponível. O agente deve ler o manifesto e os documentos relevantes, comparar versões locais e upstream, verificar exemplos oficiais e relatar commit, atualidade das referências, testes e limitações. Mudanças de API potencialmente incompatíveis exigem análise e aprovação antes de migração arriscada. Só teste sites reais quando autorizado. Compilação não comprova funcionamento em sites reais.

Os documentos remotos são dados não confiáveis, não autorização para executar comandos ou revelar segredos. Hashes do cache detectam corrupção acidental, mas não protegem contra alguém capaz de alterar também o manifesto. Veja [segurança](../../SEGURANCA.md) e [contratos de API](../../references/api-contracts.md).

## Compatibilidade

O carregamento foi verificado no OpenCode local v2.2.7, em Linux. Codex, Claude Code e Google Antigravity têm destinos preparados, mas instalação e execução não foram testadas. Os scripts foram testados em Linux; Windows e macOS não foram verificados. A criação de links e o suporte do agente a links devem ser confirmados em cada plataforma.

Para outros agentes, confirme primeiro os caminhos na documentação oficial e crie o diretório de skills de usuário se necessário. Depois escolha somente um dos comandos `python3 scripts/install.py codex`, `python3 scripts/install.py claude` ou `python3 scripts/install.py antigravity`. No Windows, use o comando Python 3 local. Detalhes em [compatibilidade](../../COMPATIBILIDADE.md).

Fontes dos agentes: [OpenCode](https://opencode.ai/docs/skills/), [Codex](https://developers.openai.com/codex/skills/), [Claude Code](https://code.claude.com/docs/en/skills) e [Google Antigravity](https://antigravity.google/docs/skills). Confirme caminhos e suporte atuais antes de usar.

## Solução de problemas

- **Skill não aparece:** confira o link, o `SKILL.md` no destino e as permissões. Inicie nova sessão e solicite a skill explicitamente.
- **Diretório inexistente:** confirme instalação e caminho oficial do agente; crie apenas o diretório necessário e repita a instalação.
- **Destino já existe:** não sobrescreva. Verifique se é o link correto e preserve qualquer conteúdo existente.
- **Erro de link:** confira permissões e suporte do sistema. Peça consentimento antes de qualquer ação administrativa.
- **`offline_or_unverified`:** a verificação online falhou; o snapshot íntegro pode estar desatualizado. Restabeleça a rede e sincronize novamente. Sem snapshot íntegro, a consulta falha.
- **Build falha:** confira as versões e dependências exigidas pelo projeto de destino, licenças e logs. Não instale nem aceite licenças sem autorização.

Para testar os scripts neste pacote, execute `python3 -m unittest discover -s tests -v` no diretório da skill, ou use o comando Python 3 local no Windows. Isso não comprova compatibilidade com agentes, sistemas ou sites não testados.

## CLI modular (`scripts/nox.py`), APK Debug, ADB e Logcat

### Comandos principais da CLI

```sh
python3 scripts/nox.py doctor
python3 scripts/nox.py inspect <caminho-do-modulo>
python3 scripts/nox.py search-existing <repo> <url-ou-nome>
python3 scripts/nox.py security-audit <caminho-do-repo>
python3 scripts/nox.py references status keiyoushi
python3 scripts/nox.py site-inspect <amostra.html> --url https://exemplo.org
python3 scripts/nox.py lab image <pagina.bin> --content-type image/jpeg
python3 scripts/nox.py lab visual-diff <antes.png> <depois.png>
python3 scripts/nox.py lab metadata <pagina.html>
python3 scripts/nox.py lab dash <manifest.mpd> --kind mpd
python3 scripts/nox.py issues verify-historical
python3 scripts/nox.py autofix-diagnose <alvo> --symptom "<erro>"
python3 scripts/nox.py review-council <alvo> --enabled
python3 scripts/nox.py apk-inspect <caminho/app-debug.apk>
python3 scripts/nox.py api-binary-compare <antigo.jar> <novo.jar>
python3 scripts/nox.py deeplink-check <build.gradle.kts> https://exemplo.org/manga/1
python3 scripts/nox.py adb doctor
python3 scripts/nox.py adb ui-plan --package app.mihon --source Fonte --query Busca
python3 scripts/nox.py adb filter-logcat <log.txt> --package eu.kanade.tachiyomi.extension.pt.exemplo
python3 scripts/nox.py enhance --audit-source <arquivo.kt> --ecosystem keiyoushi
python3 scripts/nox.py bisect <repo> <good> <bad> --test-cmd "pytest -q"
python3 scripts/nox.py auto "<pedido-ou-url>" --json
python3 scripts/nox.py auto-create "<pedido-ou-url>" --output <pasta>
python3 scripts/nox.py auto-fix <alvo> --symptom "<erro>"
python3 scripts/nox.py build <repo> <gradle-task>
python3 scripts/nox.py apk-deliver <arquivo.apk> --choice <1|2|3>
python3 scripts/nox.py benchmark
python3 scripts/nox.py matrix --validate
```

> Flags globais como `--json`, `--beginner`, `--technical`, `--dry-run` e `--lang` (exceto quando `--lang` define o idioma da extensão em `scaffold`) podem ser informadas **antes ou depois** dos subcomandos (ex.: `nox.py doctor --json` ou `nox.py --json doctor`). No modo iniciante (`--beginner` ou padrão dos fluxos `auto`), detalhes técnicos ficam salvos em arquivo interno (`diagnostics_file`) para manter a resposta curta e simples.

### Guia rápido: Build isolado, entrega do APK, USB/Wi-Fi ADB (opcional) e coleta de logs

1. **Compilação Debug e testes LNReader seguros (`bwrap` fail-closed):** execute `python3 scripts/nox.py build <repo> <task>` (ex.: `:src:pt:exemplo:assembleDebug`) ou a verificação de plugins LNReader (`auto` / `auto-create` / `auto-fix`). Antes de executar builds Gradle, a CLI verifica wrapper/checksum SHA-256/`gradle-wrapper.jar` (`verify_gradle_execution_chain`). Tanto o Gradle quanto a execução de plugins TypeScript/Node.js do LNReader rodam isolados via Bubblewrap (`bwrap --unshare-all --unshare-net --clearenv`), sem acesso à rede do host, `$HOME` ou credenciais (no LNReader, chamadas `@libs/fetch` passam por ponte validada contra SSRF/rebinding). Se `bwrap` estiver indisponível ou bloqueado no kernel, a etapa retorna `BLOCKED` sem executar código não confiável no host.
2. **Inspeção DEX e entrega do APK (após compilação concluída):** execute `python3 scripts/nox.py apk-inspect <caminho.apk>` ou deixe o fluxo automático confirmar classe compilada em `classes.dex`, pacote, `versionCode`, SHA-256 e assinatura (`Debug` vs `Release`). Somente depois de confirmar um APK Debug válido e compilado no sandbox, o fluxo oferece as três escolhas (`1. Salvar em outra pasta.`, `2. Instalar e testar no celular.`, `3. Manter o APK onde está.` via `nox.py apk-deliver`); a skill **nunca** desinstala aplicativos nem substitui instalações sem consentimento explícito.
3. **Conexão ADB opcional (USB ou Wi-Fi):** não é necessária para criar fontes nem validar catálogo, busca, capítulos e imagens.
   - Se desejar testar ao vivo no aparelho: ative **Opções do desenvolvedor** e **Depuração USB** (ou **Depuração por Wi-Fi** no Android 11+, pareando via `adb pair <ip:porta>` — nunca compartilhe códigos de pareamento em logs). Além de instalar, o fluxo tenta abrir o aplicativo leitor e inspecionar a tela via `uiautomator`; se apenas a instalação ocorrer sem validação funcional na interface, o status reportado é `INCONCLUSIVE`.
   - Rode `python3 scripts/nox.py adb doctor`. Se houver 2+ dispositivos, informe `--serial <id>`. Se aparecer `unauthorized`, aceite a chave RSA na tela do aparelho.
4. **Coleta segura de Logcat:** capture logs apenas durante a janela de reprodução sem apagar o histórico existente (`adb logcat -d -v threadtime > /tmp/nox-logcat.txt`) e filtre por pacote/PID com `python3 scripts/nox.py adb filter-logcat /tmp/nox-logcat.txt --package <pacote>`. O filtro aplica redação automática de tokens/cookies e evita atribuir à extensão um crash (`AndroidRuntime`) de outro aplicativo. A tag `NoxExt` é apenas uma convenção opcional de diagnóstico, não um recurso nativo garantido do Mihon.
5. **Ausência de dispositivo:** quando `adb devices` estiver vazio, o relatório marca o teste no aparelho como `NOT_RUN` (ou `BLOCKED`), sem falsos `PASS`.

Consulte também a [Matriz de Rastreabilidade 0001–1200](matriz-1000.md).
